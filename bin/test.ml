open Ctypes

let () = print_endline "test"

let x = allocate uint8_t (Unsigned.UInt8.of_int 42)
let y = Unsigned.Size_t.of_int 4

let z =  Ecec.Ffi.ece_aes128gcm_plaintext_max_length x y

let () = Printf.printf "z is %d\n" (Unsigned.Size_t.to_int z)
