type handle                     (* pcap_t* *)
type bpf_program                (* struct bpf_program* *)
type pcap_pkthdr = {tv_sec  :int64;
                    tv_usec :int64;
                    caplen  :int32; (* u_int32 *)
                    len     :int32} (* u_int32 *)

(* ================================================================ *)
(* http://www.tcpdump.org/linktypes.html                            *)
type link_type =
  | DLT_NULL
  | DLT_EN10MB
  | DLT_EN3MB
  | DLT_AX25
  | DLT_PRONET
  | DLT_CHAOS
  | DLT_IEEE802
  | DLT_ARCNET
  | DLT_SLIP
  | DLT_PPP
  | DLT_FDDI

exception Link_type
(* ================================================================ *)

let print_link_type = function
  | DLT_NULL    -> "NULL"
  | DLT_EN10MB  -> "EN10MB"
  | DLT_EN3MB   -> "EN3MB"
  | DLT_AX25    -> "AX25"
  | DLT_PRONET  -> "PRONET"
  | DLT_CHAOS   -> "CHAOS"
  | DLT_IEEE802 -> "IEEE802"
  | DLT_ARCNET  -> "ARCNET"
  | DLT_SLIP    -> "SLIP"
  | DLT_PPP     -> "PPP"
  | DLT_FDDI    -> "FDDI"




external pcap_open_live: string -> int -> int -> int -> (handle, string) result =
  "ppp_pcap_open_live"



external pcap_datalink_1: handle -> int =
  "ppp_pcap_datalink"



let pcap_datalink (h:handle) : link_type =
  match pcap_datalink_1 h with
  | 0  -> DLT_NULL
  | 1  -> DLT_EN10MB
  | 2  -> DLT_EN3MB
  | 3  -> DLT_AX25
  | 4  -> DLT_PRONET
  | 5  -> DLT_CHAOS
  | 6  -> DLT_IEEE802
  | 7  -> DLT_ARCNET
  | 8  -> DLT_SLIP
  | 9  -> DLT_PPP
  | 10 -> DLT_FDDI
  | _  -> raise Link_type

(* (net, mask): int32*int32   *)
(* actually, NET and MASK is u_int *)
external pcap_lookupnet: string -> (int32*int32, string) result =
  "ppp_pcap_lookupnet"


(* 	int pcap_compile(pcap_t *p, struct bpf_program *fp,
		   const char *str, int optimize, bpf_u_int32 netmask);
 *)
external pcap_compile: handle -> string -> bool -> int32 -> (bpf_program, int) result =
  "ppp_pcap_compile"


(* 	int pcap_setfilter(pcap_t *p, struct bpf_program *fp); *)
external pcap_setfilter: handle -> bpf_program -> int =
  "ppp_pcap_setfilter"

(* 	int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user);
   not provide CALLBACK because we use `registration mechanism' way to 
   pass ocaml-callback func to C
*)
external pcap_loop: handle -> int -> (* callback ->  *)bytes -> int =
  "ppp_pcap_loop"

(* pcap_loop callback func sig:                                               *)
(*   typedef void (\*pcap_handler)(u_char *user, const struct pcap_pkthdr *h, *)
(*   	   			     const u_char *bytes);                    *)
(* this is an example pcap_handler function                                   *)
(* so users should impl it by themselves and apply Init.init on it            *)
let pcap_handler (user: bytes) (h:pcap_pkthdr) (bytes:bytes) : unit =
  Printf.printf "len:%d, caplen:%d\n" (Int32.to_int h.len) (Int32.to_int h.caplen);
  let isprint c = Char.compare c ' ' >= 0 && Char.compare c '~' <= 0 in
  let print_content content = content |> Bytes.iter (fun c ->
      if isprint c then print_char c
      else print_char '.')  in
  print_content bytes

module Init = struct
  type pcap_handler_t = bytes -> pcap_pkthdr -> bytes -> unit  
  let init (h:pcap_handler_t) =
    Callback.register "pcap_handler" h;
    
end

(* Interfacing C with OCaml *)
(* http://caml.inria.fr/pub/docs/manual-ocaml/intfc.html *)
