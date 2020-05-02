(* Hack needed to make symbols available, see constfun's comment here
 * https://github.com/ocamllabs/ocaml-ctypes/issues/541 *)
external _force_link_ : unit -> unit = "ece_aes128gcm_plaintext_max_length"

open Ctypes
open Foreign

let ece_aes128gcm_plaintext_max_length =
  foreign "ece_aes128gcm_plaintext_max_length"
    (ptr uint8_t @-> size_t @-> returning size_t)
