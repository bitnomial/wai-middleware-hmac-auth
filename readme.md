# wai-middleware-hmac-auth

This package provides support for some common tasks in HMAC based auth. One of the core features of this library is that the signing/verification algorithms may touch the body of a request without interfering with the rest of the handling process.

## Default scheme

Use `hmacAuth` to build a scheme which uses headers for the client identity and signature. The HMAC signature covers:

- Method
- Path
- Entire query string
- Subset of headers determined by a filter
- Request body

## Sign a client request

We configure the `Manager` used to manage connections for the client sessions with a request modifier:

```haskell
auth :: HmacAuth SHA256 Text
auth = hmacAuth "X-Identity" "X-Signature" (== "X-Identity")

getAuthKey :: IO AuthKey
getAuthKey = mkAuthKey <$> getEnv "AUTH_KEY"

main :: IO ()
main = do
  mgr <- newManager defaultManagerSettings { managerModifyRequest = hmacSignRequest auth "client-id" getAuthKey }
  _use mgr
```

## Verify a client request

We define a Wai Middleware which verifies signatures.

```haskell
auth :: HmacAuth SHA256 Text
auth = hmacAuth "X-Identity" "X-Signature" (== "X-Identity")

-- Lookup the key for a given identity
getAuthKey :: Text -> IO AuthKey
getAuthKey = _

main :: IO ()
main = Warp.run port $ hmacAuthMiddleware getAuthKey auth _app
```
