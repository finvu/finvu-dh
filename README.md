# finvu-dh
Finvu Diffie Hellman Example

This example project demonstrates encryption and decryption using Diffie Hellman Key Exchange in the Curve25519 group.

A 256 bit AES session key is generated using the shared secret, a UUID nonce of the intiator and a UUID nonce of the encrypter.

The session key thus calculated is used for encryption and decryption.

Session key is never sent over the network.

Refer to Curve25519Test for working example and additional comments.
