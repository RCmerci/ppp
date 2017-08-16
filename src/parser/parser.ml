

let datalink_layer_length = function
  | Pcap.DLT_NULL -> Some 4
  | Pcap.DLT_EN10MB -> Some 14
  | Pcap.DLT_SLIP | Pcap.DLT_PPP -> Some 24
  | _ -> None

(* to easy to identify, for example                         *)
(*  `flags3_fragment_offset13` in type `ipv4_internal.ipv4` *)
(* 3 : 3 bits for flags                                     *)
(* 13 : 13 bits for fragment_offset                         *)

[%%cstruct
type ethernet = {
  dst       : int8 [@len 6];
  src       : uint8_t [@len 6];
  ethertype : uint16_t;
} [@@big_endian]]

[%%cstruct
  type ipv4 = {
    version4_ihl4            : uint8;
    ds_field4_ecn4           : uint8;
    total_length             : uint16;
    id                       : uint16;
    flags3_fragment_offset13 : uint16;
    ttl                      : uint8;
    protocol                 : uint8;
    header_checksum          : uint16;
    src                      : uint32;
    dst                      : uint32;
  }[@@big_endian]]

let split_ipv4_option ipv4_hdr rest =
  let ihl = get_ipv4_version4_ihl4 ipv4_hdr |> (land) 0xf in
  Cstruct.split rest (ihl*4 - sizeof_ipv4)

(* tcp header format *)
(* http://freesoft.org/CIE/Course/Section4/8.htm *)
[%%cstruct
  type tcp = {
    src_port                 : uint16;
    dst_port                 : uint16;
    seq                      : uint32;
    ack                      : uint32;
    header_length4_reserved4 : uint8;
    ctrl_bits                : uint8;
    window                   : uint16;
    checksum                 : uint16;
    urgent_pointer           : uint16;
  }[@@big_endian]]

let split_tcp_option tcp rest =
  let header_length = (get_tcp_header_length4_reserved4 tcp) lsr 4 in
  Cstruct.split rest (header_length*4 - sizeof_tcp)
  

let split_datalink bytes typ =
  let v = Cstruct.of_bytes bytes in
  let datalink_len = datalink_layer_length typ in
  match datalink_len with
  | None -> raise @@ Invalid_argument "typ"
  | Some l -> let (h, t) = Cstruct.split v l in (h, t)


let split_ipv4 v =
  let (ipv4, t) = Cstruct.split v sizeof_ipv4 in
  let (opt, rest) = split_ipv4_option ipv4 t in
  (ipv4, opt, rest)


let split_tcp v =
  let (tcp, t) = Cstruct.split v sizeof_tcp in
  let (opt, rest) = split_tcp_option tcp t in
  (tcp, opt, rest)
