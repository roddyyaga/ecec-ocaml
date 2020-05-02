open Base
open Ctypes

let string_of_carray a = String.of_char_list @@ CArray.to_list a

let aes128gcm_encrypt ?(pad_len = 0) ~p256dh ~auth plaintext =
  let module Size_t = Unsigned.Size_t in
  let plaintext_len = String.length plaintext in
  let raw_recv_pub_key = CArray.make char Ffi._ECE_WEBPUSH_PUBLIC_KEY_LENGTH in
  let raw_recv_pub_key_len =
    Ffi.ece_base64url_decode
      CArray.(start @@ of_string p256dh)
      (Size_t.of_int @@ String.length p256dh)
      Ffi.ECE_BASE64URL_REJECT_PADDING
      CArray.(start raw_recv_pub_key)
      (Size_t.of_int Ffi._ECE_WEBPUSH_PUBLIC_KEY_LENGTH)
  in
  let auth_secret = CArray.make char Ffi._ECE_WEBPUSH_AUTH_SECRET_LENGTH in
  let auth_secret_len =
    Ffi.ece_base64url_decode
      CArray.(start @@ of_string auth)
      (Size_t.of_int @@ String.length auth)
      Ffi.ECE_BASE64URL_REJECT_PADDING
      CArray.(start auth_secret)
      (Size_t.of_int Ffi._ECE_WEBPUSH_AUTH_SECRET_LENGTH)
  in
  let payload_len =
    Ffi.ece_aes128gcm_payload_max_length
      (Unsigned.UInt32.of_int Ffi._ECE_WEBPUSH_DEFAULT_RS)
      (Size_t.of_int pad_len)
      (Size_t.of_int plaintext_len)
  in
  let payload = CArray.make char (Size_t.to_int payload_len) in
  let payload_len_ptr = allocate size_t payload_len in
  let _err =
    Ffi.ece_webpush_aes128gcm_encrypt
      CArray.(start raw_recv_pub_key)
      raw_recv_pub_key_len
      CArray.(start auth_secret)
      auth_secret_len
      (Unsigned.UInt32.of_int Ffi._ECE_WEBPUSH_DEFAULT_RS)
      (Size_t.of_int pad_len)
      CArray.(start @@ of_string plaintext)
      (Size_t.of_int plaintext_len)
      CArray.(start payload)
      payload_len_ptr
  in
  string_of_carray payload
