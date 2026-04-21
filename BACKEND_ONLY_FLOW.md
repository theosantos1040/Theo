# Backend-only protection flow

1. Customer creates account
2. Customer generates keys
3. Frontend uses only publicId
4. Backend verifies with secret
5. Secret never goes to the browser
