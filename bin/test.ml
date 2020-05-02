let () = print_endline "test"

let p256dh =
  "BDwwYm4O5dZG9SO6Vaz168iDLGWMmitkj5LFvunvMfgmI2fZdAEaiHTDfKR0fvr0D3V56cSGSeUwP0xNdrXho5k"

let auth = "xcmQLthL5H2pJNuxrZO-qQ"

let plaintext = "Test message 123"

let output = Ecec.Encryption.aes128gcm_encrypt ~p256dh ~auth plaintext

let () = print_endline output
