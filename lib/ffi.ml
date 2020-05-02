(* Hack needed to make symbols available, see constfun's comment here
 * https://github.com/ocamllabs/ocaml-ctypes/issues/541 
 *
 * For some reason we appear to need this for some particular symbols *)
external _force_link_ : unit -> unit = "ece_aes128gcm_plaintext_max_length"

external _force_link_ : unit -> unit = "ece_aes128gcm_payload_max_length"

open Ctypes
open Foreign

let _ECE_SALT_LENGTH = 16

let _ECE_TAG_LENGTH = 16

let _ECE_WEBPUSH_PRIVATE_KEY_LENGTH = 32

let _ECE_WEBPUSH_PUBLIC_KEY_LENGTH = 65

let _ECE_WEBPUSH_AUTH_SECRET_LENGTH = 16

let _ECE_WEBPUSH_DEFAULT_RS = 4096

let ece_aes128gcm_plaintext_max_length =
  foreign "ece_aes128gcm_plaintext_max_length"
    (ptr char @-> size_t @-> returning size_t)

let ece_webpush_generate_keys =
  foreign "ece_webpush_generate_keys"
    ( ptr char @-> size_t @-> ptr char @-> size_t @-> ptr char @-> size_t
    @-> returning int )

type ece_base64url_decode_policy_e =
  | ECE_BASE64URL_REQUIRE_PADDING
  | ECE_BASE64URL_IGNORE_PADDING
  | ECE_BASE64URL_REJECT_PADDING
[@@deriving enum]

let ece_base64url_decode_policy_e =
  view
    ~read:(fun i -> Option.get @@ ece_base64url_decode_policy_e_of_enum i)
    ~write:ece_base64url_decode_policy_e_to_enum Ctypes.int

let ece_base64url_decode =
  foreign "ece_base64url_decode"
    ( ptr char @-> size_t @-> ece_base64url_decode_policy_e @-> ptr char
    @-> size_t @-> returning size_t )

let ece_aes128gcm_payload_max_length =
  foreign "ece_aes128gcm_payload_max_length"
    (uint32_t @-> size_t @-> size_t @-> returning size_t)

let ece_webpush_aes128gcm_encrypt =
  foreign "ece_webpush_aes128gcm_encrypt"
    ( ptr char @-> size_t @-> ptr char @-> size_t @-> uint32_t @-> size_t
    @-> ptr char @-> size_t @-> ptr char @-> ptr size_t @-> returning int )
