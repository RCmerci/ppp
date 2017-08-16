open Printf


let datalink_type:Pcap.Link_type ref = ref 1

let pcap_handler (user: bytes) (h:Pcap.pcap_pkthdr) (bytes:bytes) = 
  Parser.split_datalink bytes 
    Pcap.pcap_datalink


let compile_and_set h net =
  match Pcap.pcap_compile h "port 8009" true net with
    Ok pf -> let _ =
               Pcap.pcap_setfilter h pf |> printf "setfilter:%d\n"; flush stdout;
               Pcap.Init.init Pcap.pcap_handler;
               Pcap.pcap_loop h 1 "";
    in ()

  | Error e -> printf "compile: %d\n" e


let _ =
  let r = Pcap.pcap_open_live "en0" 1000 1 1000 in
  match r with
    Ok h -> 
    (let r = Pcap.pcap_lookupnet "en0" in
     match r with
       Ok (net, mask) -> compile_and_set h net
     | Error e -> Printf.printf "%s\n" e);
  | Error e -> Printf.printf "%s" e
