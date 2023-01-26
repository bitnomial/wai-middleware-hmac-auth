{-# LANGUAGE DataKinds #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# OPTIONS_GHC -Wno-deprecations #-}

-- |
-- Module: Network.Wai.Middleware.Auth.HMAC
--
-- This module contains a framework for building an HMAC auth system.
module Network.Wai.Middleware.Auth.HMAC (
    -- * Keys
    AuthKey,
    mkAuthKey,
    encodeAuthKey,

    -- * Framework
    HmacAuth (..),
    hmacAuth,
    requestSignature,
    verifySignature,
    HmacError (..),

    -- * Request processing
    HmacRequest (..),
    waiToHmacRequest,
    clientToHmacRequest,

    -- * Server
    hmacVerifyMiddleware,

    -- * Client
    hmacSignRequest,

    -- * Re-exports
    SHA256,
    SHA512,
    SHA3_256,
    SHA3_512,
) where

import Control.Monad (unless, (<=<))
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Except (runExceptT, throwE)
import Crypto.Hash (HashAlgorithm, SHA256, SHA3_256, SHA3_512, SHA512)
import Crypto.MAC.HMAC (HMAC, hmacLazy)
import qualified Data.ByteArray as BA
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as BS8
import Data.ByteString.Lazy (LazyByteString)
import qualified Data.ByteString.Lazy as BSL
import qualified Data.CaseInsensitive as CI
import Data.IORef (atomicModifyIORef, newIORef)
import Data.List (sortOn, uncons)
import qualified Data.Text as Text
import Data.Text.Encoding (encodeUtf8)
import Data.Time (defaultTimeLocale, formatTime, getCurrentTime)
import Data.Tuple (swap)
import qualified Network.HTTP.Client as HttpClient
import Network.HTTP.Types (Header, HeaderName, Method, RequestHeaders, status400, status401)
import Network.Wai (Middleware)
import qualified Network.Wai as Wai
import Web.HttpApiData (FromHttpApiData, ToHttpApiData, parseHeader, toHeader)


-- | An opaque representation of key material
newtype AuthKey = AuthKey {unAuthKey :: ByteString}
    deriving (Eq, Ord)


instance Show AuthKey where
    show _ = "AuthKey {unAuthKey = \"REDACTED\"}"


mkAuthKey :: ByteString -> AuthKey
mkAuthKey = AuthKey


encodeAuthKey :: AuthKey -> ByteString
encodeAuthKey = unAuthKey


-- | A collection of the request fields which might be used in an HMAC auth
-- message digest
data HmacRequest = HmacRequest
    { method :: Method
    , path :: ByteString
    , queryString :: ByteString
    , headers :: RequestHeaders
    , body :: LazyByteString
    }
    deriving (Eq, Show)


waiToHmacRequest ::
    Wai.Request ->
    -- | Request body
    LazyByteString ->
    HmacRequest
waiToHmacRequest request requestBody =
    HmacRequest
        { method = Wai.requestMethod request
        , path = Wai.rawPathInfo request
        , queryString = Wai.rawQueryString request
        , headers = Wai.requestHeaders request
        , body = requestBody
        }


-- | Currently this only supports conversion when the body is 'RequestBodyBS' or 'RequestBodyLBS'
clientToHmacRequest :: HttpClient.Request -> HmacRequest
clientToHmacRequest request =
    HmacRequest
        { method = HttpClient.method request
        , path = HttpClient.path request
        , queryString = HttpClient.queryString request
        , headers = HttpClient.requestHeaders request
        , body = toByteString $ HttpClient.requestBody request
        }
  where
    toByteString = \case
        HttpClient.RequestBodyBS body -> BSL.fromStrict body
        HttpClient.RequestBodyLBS body -> body
        _ -> error "getHttpClientRequestBody: body type not supported"


-- | Request processing logic.  Use the 'hashAlgorithm' type parameter to select
-- the hashing algorithm.
data HmacAuth hashAlgorithm id = HmacAuth
    { requestDigest :: HmacRequest -> LazyByteString
    -- ^ Calculate the message that the authenticating identity should sign
    , extractIdentity :: HmacRequest -> Maybe id
    -- ^ Pull the authenticating identity out of the request
    , setIdentity :: id -> HttpClient.Request -> HttpClient.Request
    -- ^ Attach the authenticating identity to the request
    , extractSignature :: HmacRequest -> Maybe ByteString
    -- ^ Pull the signature out of the request
    , setSignature :: ByteString -> HttpClient.Request -> HttpClient.Request
    -- ^ Attach the signature to the request
    , extractTimestamp :: HmacRequest -> Maybe Text.Text
    -- ^ Pull the timestamp out of the request
    , setTimestamp :: Text.Text -> HttpClient.Request -> HttpClient.Request
    -- ^ Attach the timestamp to the request
    }


-- | This is a canned request digest to use:
--
-- @$METHOD$PATH$QUERYSTRING$HEADERS$BODY@
hmacAuth ::
    (FromHttpApiData id, ToHttpApiData id) =>
    -- | Identity header e.g. @X-Identity@
    HeaderName ->
    -- | Signature header e.g. @X-Signature@
    HeaderName ->
    -- | Timestamp header in seconds since Unix Epoch e.g. @X-Timestamp@
    HeaderName ->
    -- | Filter the set of headers to include in the message
    (HeaderName -> Bool) ->
    HmacAuth a id
hmacAuth identityHeader signatureHeader timestampHeader includeHeader =
    HmacAuth
        { requestDigest
        , extractIdentity
        , setIdentity
        , extractSignature
        , setSignature
        , extractTimestamp
        , setTimestamp
        }
  where
    requestDigest request =
        (mconcat . fmap BSL.fromStrict)
            ( [ maybe "" encodeUtf8 $ extractTimestamp request
              , method request
              , normalizePath $ path request
              , normalizeQMark $ queryString request
              ]
                <> [ CI.original name <> value | (name, value) <- sortOn fst . filter (includeHeader . fst) $ headers request
                   ]
            )
            <> body request
    normalizePath qs
        | Just ('/', _) <- BS8.uncons qs = qs
        | otherwise = BS8.cons '/' qs
    normalizeQMark qs
        | Just ('?', _) <- BS8.uncons qs = qs
        | otherwise = BS8.cons '?' qs

    extractIdentity =
        (either (const Nothing) pure . parseHeader <=< lookup identityHeader) . headers
    setIdentity theIdentity request =
        request
            { HttpClient.requestHeaders =
                setHeader (identityHeader, toHeader theIdentity) $ HttpClient.requestHeaders request
            }
    extractSignature = (either (const Nothing) Just . B64.decode <=< lookup signatureHeader) . headers
    setSignature sig request =
        request
            { HttpClient.requestHeaders =
                setHeader (signatureHeader, B64.encode sig) $ HttpClient.requestHeaders request
            }
    extractTimestamp = (either (const Nothing) pure . parseHeader <=< lookup timestampHeader) . headers
    setTimestamp theTimestamp request =
        request
            { HttpClient.requestHeaders =
                setHeader (timestampHeader, toHeader theTimestamp) $ HttpClient.requestHeaders request
            }


setHeader :: Header -> RequestHeaders -> RequestHeaders
setHeader h@(hName, hValue) = \case
    someH@(someName, _) : hs
        | someName == hName -> (someName, hValue) : hs
        | otherwise -> someH : setHeader h hs
    _ -> [h]


requestSignature ::
    forall a id.
    HashAlgorithm a =>
    HmacAuth a id ->
    AuthKey ->
    HmacRequest ->
    ByteString
requestSignature auth (AuthKey authKey) =
    BA.convert @(HMAC a) @ByteString
        . hmacLazy authKey
        . requestDigest auth


verifySignature ::
    (Monad m, HashAlgorithm a) =>
    HmacAuth a id ->
    -- | Get the siging key from the identity
    (id -> m (Maybe AuthKey)) ->
    HmacRequest ->
    m (Either (HmacError id) ())
verifySignature auth getAuthKey request = runExceptT $ do
    authId <- maybe (throwE UnknownIdentity) pure $ extractIdentity auth request
    sig <- maybe (throwE $ NoSignature authId) pure $ extractSignature auth request
    authKey <- maybe (throwE $ UnknownKey authId) pure =<< lift (getAuthKey authId)
    unless (sig == requestSignature auth authKey request) . throwE $ InvalidSignature authId


data HmacError id
    = -- | Unable to parse the identity value
      UnknownIdentity
    | -- | Unable to parse the signature
      NoSignature id
    | -- | Key lookup failed
      UnknownKey id
    | -- | Signature is invalid
      InvalidSignature id


hmacVerifyMiddleware ::
    forall a id.
    HashAlgorithm a =>
    HmacAuth a id ->
    -- | Get key for identity
    (id -> IO (Maybe AuthKey)) ->
    Middleware
hmacVerifyMiddleware auth getAuthKey app request withResponse = do
    requestBody <- Wai.strictRequestBody request
    verifySignature auth getAuthKey (waiToHmacRequest request requestBody)
        >>= either onError (onSuccess requestBody)
  where
    -- Replace the request body so that downstream users can consume it
    onSuccess requestBody _ = do
        refBody <- newIORef $ BSL.toChunks requestBody
        app
            request
                { Wai.requestBody = atomicModifyIORef refBody $ maybe mempty swap . uncons
                }
            withResponse

    onError =
        withResponse . \case
            UnknownIdentity ->
                Wai.responseBuilder
                    status400
                    mempty
                    "Unable to parse authenticating identity from request"
            NoSignature{} ->
                Wai.responseBuilder
                    status400
                    mempty
                    "Unable to parse signature from request"
            UnknownKey{} -> unauthorized
            InvalidSignature{} -> unauthorized
    unauthorized =
        Wai.responseBuilder
            status401
            mempty
            mempty


-- | Upgrade a 'Manager' to sign requests. For example:
--
-- >>> mgr <- newManager defaultManagerSettings { managerModifyRequest = hmacSignRequest _auth _id _getAuthKey }
hmacSignRequest ::
    forall a id.
    HashAlgorithm a =>
    HmacAuth a id ->
    -- | Client identity
    id ->
    -- | Get the current API key
    IO AuthKey ->
    HttpClient.Request ->
    IO HttpClient.Request
hmacSignRequest auth signerId getAuthKey request = do
    authKey <- getAuthKey
    secondsSinceEpoch <- Text.pack . formatTime defaultTimeLocale "%s" <$> getCurrentTime
    pure $ setSignature auth (sig authKey secondsSinceEpoch) (requestToSign secondsSinceEpoch)
  where
    sig authKey ts = requestSignature auth authKey . clientToHmacRequest $ requestToSign ts
    requestToSign ts = setIdentity auth signerId (requestWithTimestamp ts)
    requestWithTimestamp ts = setTimestamp auth ts request
