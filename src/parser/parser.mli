val datalink_layer_length : Pcap.link_type -> int option
(** [datalink_layer_length typ] is length of datalink type [typ] if [typ] is 
    supported *)

(** cstruct generate following functions  *)
val sizeof_ethernet : int
val get_ethernet_dst : Cstruct.t -> Cstruct.t
val copy_ethernet_dst : Cstruct.t -> string
val set_ethernet_dst : string -> int -> Cstruct.t -> unit
val blit_ethernet_dst : Cstruct.t -> int -> Cstruct.t -> unit
val get_ethernet_src : Cstruct.t -> Cstruct.t
val copy_ethernet_src : Cstruct.t -> string
val set_ethernet_src : string -> int -> Cstruct.t -> unit
val blit_ethernet_src : Cstruct.t -> int -> Cstruct.t -> unit
val get_ethernet_ethertype : Cstruct.t -> Cstruct.uint16
val set_ethernet_ethertype : Cstruct.t -> Cstruct.uint16 -> unit
val hexdump_ethernet_to_buffer : Buffer.t -> Cstruct.t -> unit
val hexdump_ethernet : Cstruct.t -> unit
val sizeof_ipv4 : int
val get_ipv4_version4_ihl4 : Cstruct.t -> Cstruct.uint8
val set_ipv4_version4_ihl4 : Cstruct.t -> Cstruct.uint8 -> unit
val get_ipv4_ds_field4_ecn4 : Cstruct.t -> Cstruct.uint8
val set_ipv4_ds_field4_ecn4 : Cstruct.t -> Cstruct.uint8 -> unit
val get_ipv4_total_length : Cstruct.t -> Cstruct.uint16
val set_ipv4_total_length : Cstruct.t -> Cstruct.uint16 -> unit
val get_ipv4_id : Cstruct.t -> Cstruct.uint16
val set_ipv4_id : Cstruct.t -> Cstruct.uint16 -> unit
val get_ipv4_flags3_fragment_offset13 : Cstruct.t -> Cstruct.uint16
val set_ipv4_flags3_fragment_offset13 : Cstruct.t -> Cstruct.uint16 -> unit
val get_ipv4_ttl : Cstruct.t -> Cstruct.uint8
val set_ipv4_ttl : Cstruct.t -> Cstruct.uint8 -> unit
val get_ipv4_protocol : Cstruct.t -> Cstruct.uint8
val set_ipv4_protocol : Cstruct.t -> Cstruct.uint8 -> unit
val get_ipv4_header_checksum : Cstruct.t -> Cstruct.uint16
val set_ipv4_header_checksum : Cstruct.t -> Cstruct.uint16 -> unit
val get_ipv4_src : Cstruct.t -> Cstruct.uint32
val set_ipv4_src : Cstruct.t -> Cstruct.uint32 -> unit
val get_ipv4_dst : Cstruct.t -> Cstruct.uint32
val set_ipv4_dst : Cstruct.t -> Cstruct.uint32 -> unit
val hexdump_ipv4_to_buffer : Buffer.t -> Cstruct.t -> unit
val hexdump_ipv4 : Cstruct.t -> unit
val sizeof_tcp : int
val get_tcp_src_port : Cstruct.t -> Cstruct.uint16
val set_tcp_src_port : Cstruct.t -> Cstruct.uint16 -> unit
val get_tcp_dst_port : Cstruct.t -> Cstruct.uint16
val set_tcp_dst_port : Cstruct.t -> Cstruct.uint16 -> unit
val get_tcp_seq : Cstruct.t -> Cstruct.uint32
val set_tcp_seq : Cstruct.t -> Cstruct.uint32 -> unit
val get_tcp_ack : Cstruct.t -> Cstruct.uint32
val set_tcp_ack : Cstruct.t -> Cstruct.uint32 -> unit
val get_tcp_header_length4_reserved4 : Cstruct.t -> Cstruct.uint8
val set_tcp_header_length4_reserved4 : Cstruct.t -> Cstruct.uint8 -> unit
val get_tcp_ctrl_bits : Cstruct.t -> Cstruct.uint8
val set_tcp_ctrl_bits : Cstruct.t -> Cstruct.uint8 -> unit
val get_tcp_window : Cstruct.t -> Cstruct.uint16
val set_tcp_window : Cstruct.t -> Cstruct.uint16 -> unit
val get_tcp_checksum : Cstruct.t -> Cstruct.uint16
val set_tcp_checksum : Cstruct.t -> Cstruct.uint16 -> unit
val get_tcp_urgent_pointer : Cstruct.t -> Cstruct.uint16
val set_tcp_urgent_pointer : Cstruct.t -> Cstruct.uint16 -> unit
val hexdump_tcp_to_buffer : Buffer.t -> Cstruct.t -> unit
val hexdump_tcp : Cstruct.t -> unit




val split_ipv4_option : Cstruct.t -> Cstruct.t -> Cstruct.t * Cstruct.t
(** [split_ipv4_option ipv4 rest] return ipv4 option field and [rest] without it *)
                                                                
val split_tcp_option : Cstruct.t -> Cstruct.t -> Cstruct.t * Cstruct.t
(** [split_tcp_option tcp rest] return tcp option field and [rest] without it *)
                                                               
val split_datalink : Bytes.t -> Pcap.link_type -> Cstruct.t * Cstruct.t
(** [split_datalink bytes typ] split [bytes] into datalink header and rest content *)

val split_ipv4 : Cstruct.t -> Cstruct.t * Cstruct.t * Cstruct.t
(** [split_ipv4 v] split [v] into ipv4 header, ipv4 option and rest content *)
                                                        
val split_tcp : Cstruct.t -> Cstruct.t * Cstruct.t * Cstruct.t
(** [split_tcp v] split [v] into tcp header, tcp option and rest content *)
