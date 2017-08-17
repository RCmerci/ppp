open Printf


let datalink_type:Pcap.link_type ref = ref Pcap.DLT_NULL

let pcap_handler (user: bytes) (h:Pcap.pcap_pkthdr) (bytes:bytes) =
  let (h, t) = Parser.split_datalink bytes !datalink_type in
  let (ipv4, ipv4_opt, t') = Parser.split_ipv4 t in
  let (tcp, tcp_opt, t'') = Parser.split_tcp t' in
  let isprint c = Char.compare c ' ' >= 0 && Char.compare c '~' <= 0 in
  let print_data t = Cstruct.to_string t |> String.iter (fun c ->
      if isprint c then print_char c
      else print_char '.') in
  Parser.hexdump_ipv4 ipv4;
  Parser.hexdump_tcp tcp;
  print_data t''

let compile_and_set h net =
  match Pcap.pcap_compile h "port 8009" true net with
    Ok pf -> ( Pcap.pcap_setfilter h pf |> printf "setfilter:%d\n"; flush stdout;
               Pcap.Init.init pcap_handler;
               Pcap.pcap_loop h 1 ""|>ignore)
  | Error e -> printf "compile: %d\n" e


let _ =
  let r = Pcap.pcap_open_live "lo0" 1000 1 1000 in
  match r with
    Ok h -> (let r = Pcap.pcap_lookupnet "lo0 " in
             match r with
               Ok (net, mask) -> (let _ = datalink_type := Pcap.pcap_datalink h;
                                    print_string @@ Pcap.print_link_type !datalink_type;
                                    compile_and_set h net in ())
             | Error e -> Printf.printf "%s\n" e);
  | Error e -> Printf.printf "%s" e
