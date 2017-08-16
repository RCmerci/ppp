#include <assert.h>
#include <caml/alloc.h>
#include <caml/callback.h>
#include <caml/custom.h>
#include <caml/fail.h>
#include <caml/memory.h>
#include <caml/mlvalues.h>
#include <stdlib.h>

#include <pcap.h>

#define pcap_t_ptr_val(v) (*(pcap_t **)Data_custom_val(v))
static struct custom_operations pcap_t_custom_operations = {
    (char *)"pcap_t_custom_operations",
    custom_finalize_default,
    custom_compare_default,
    custom_hash_default,
    custom_serialize_default,
    custom_deserialize_default};

#define bpf_program_ptr_val(v) (*(struct bpf_program **)Data_custom_val(v))
static struct custom_operations bpf_program_custom_operations = {
    (char *)"bpf_program_custom_operations",
    custom_finalize_default,
    custom_compare_default,
    custom_hash_default,
    custom_serialize_default,
    custom_deserialize_default};

static pcap_t *ppp_pcap_open_live_1(char *device, int snaplen, int promisc,
				    int to_ms, char *ebuf);

CAMLprim value ppp_pcap_open_live(value device, value snaplen, value promisc,
				  value to_ms)
{
	CAMLparam4(device, snaplen, promisc, to_ms);
	CAMLlocal2(rv, v);
	char ebuf[PCAP_ERRBUF_SIZE];

	pcap_t *handle =
	    ppp_pcap_open_live_1(String_val(device), Int_val(snaplen),
				 Int_val(promisc), Int_val(to_ms), ebuf);
	if (NULL == handle) {
		rv = caml_alloc(1, 1);
		v = caml_copy_string(ebuf);
		Store_field(rv, 0, v);
	} else {
		rv = caml_alloc(1, 0);
		v = caml_alloc_custom(&pcap_t_custom_operations,
				      sizeof(pcap_t *), 0, 1);
		pcap_t_ptr_val(v) = handle;
		Store_field(rv, 0, v);
	}

	CAMLreturn(rv);
}

pcap_t *ppp_pcap_open_live_1(char *device, int snaplen, int promisc, int to_ms,
			     char *ebuf)
{
	pcap_t *handle = pcap_open_live(device, snaplen, promisc, to_ms, ebuf);
	return handle;
}

CAMLprim value ppp_pcap_datalink(value handle)
{
	CAMLparam1(handle);
	CAMLlocal1(rv);
	pcap_t *handle_ = pcap_t_ptr_val(handle);
	int r = pcap_datalink(handle_);
	rv = Int_val(r);
	CAMLreturn(rv);
}

CAMLprim value ppp_pcap_lookupnet(value device)
{
	CAMLparam1(device);
	CAMLlocal2(rv, v);
	char *device_ = String_val(device);
	bpf_u_int32 net;
	bpf_u_int32 mask;
	char errbuf[PCAP_ERRBUF_SIZE];
	int r = pcap_lookupnet(device_, &net, &mask, errbuf);
	if (0 != r) {
		rv = caml_alloc(1, 1);
		v = caml_copy_string(errbuf);
		Store_field(rv, 0, v);
	} else {
		rv = caml_alloc(1, 0);
		v = caml_alloc(2, 0);
		Store_field(v, 0, caml_copy_int32((int32_t)net));
		Store_field(v, 1, caml_copy_int32((int32_t)mask));
		Store_field(rv, 0, v);
	}
	CAMLreturn(rv);
}

CAMLprim value ppp_pcap_compile(value handle, value str, value optimize,
				value netmask)
{
	CAMLparam4(handle, str, optimize, netmask);
	CAMLlocal2(rv, v);

	pcap_t *handle_ = pcap_t_ptr_val(handle);
	char *str_ = String_val(str);
	int optimize_ = Int_val(optimize);
	bpf_u_int32 netmask_ = (bpf_u_int32)Int32_val(netmask);
	struct bpf_program *bpf_program_ = malloc(sizeof(struct bpf_program));
	int e = pcap_compile(handle_, bpf_program_, str_, optimize_, netmask_);
	if (0 != e) {
		rv = caml_alloc(1, 1);
		v = Val_int(e);
		Store_field(rv, 0, v);
	} else {
		rv = caml_alloc(1, 0);
		v = caml_alloc_custom(&bpf_program_custom_operations,
				      sizeof(struct bpf_program *), 0, 1);
		bpf_program_ptr_val(v) = bpf_program_;
		Store_field(rv, 0, v);
	}
	CAMLreturn(rv);
}

CAMLprim value ppp_pcap_setfilter(value handle, value fp)
{
	CAMLparam2(handle, fp);

	pcap_t *handle_ = pcap_t_ptr_val(handle);
	struct bpf_program *fp_ = bpf_program_ptr_val(fp);
	int e = pcap_setfilter(handle_, fp_);
	CAMLreturn(Int_val(e));
}

CAMLprim value ppp_pcap_freecode(value fp)
{
	CAMLparam1(fp);
	struct bpf_program *fp_ = bpf_program_ptr_val(fp);
	pcap_freecode(fp_);
	CAMLreturn(Val_int(0));
}

/* -------------------------------------------------------------------	*/
/* struct pcap_pkthdr {							*/
/* 	struct timeval ts;	/\* time stamp *\/			*/
/* 	bpf_u_int32 caplen;	/\* length of portion present *\/	*/
/* 	bpf_u_int32 len;	/\* length this packet (off wire) *\/	*/
/* #ifdef __APPLE__							*/
/* 	char comment[256];						*/
/* #endif								*/
/* };									*/

static value pcap_pkthdr2caml_pcap_pkthdr(const struct pcap_pkthdr *h)
{
	value tv_sec = caml_copy_int64((long long)(h->ts.tv_sec));
	value tv_usec = caml_copy_int64((long long)(h->ts.tv_usec));
	value caplen = caml_copy_int32((int32_t)(h->caplen));
	value len = caml_copy_int32((int32_t)(h->len));
	value rv = caml_alloc(4, 0);
	Store_field(rv, 0, tv_sec);
	Store_field(rv, 1, tv_usec);
	Store_field(rv, 2, caplen);
	Store_field(rv, 3, len);
	return rv;
}

/* TODO: is there any better way to copy `h->len' bytes to ocaml value */
void ppp_pcap_handler(u_char *user, const struct pcap_pkthdr *h,
		      const u_char *bytes)
{
	assert(h->len >= h->caplen); /* i don't know diff on len and caplen */

	value pkthdr = pcap_pkthdr2caml_pcap_pkthdr(h);
	value bytes_ = caml_alloc_string(h->len);
	for (int i = 0; i < h->len; i++) {
		Byte(bytes_, i) = bytes[i];
	}
	caml_callback3(*caml_named_value("pcap_handler"),
		       caml_copy_string((char *)user), pkthdr, bytes_);
}

CAMLprim value ppp_pcap_loop(value handle, value cnt, value user)
{
	CAMLparam3(handle, cnt, user);
	CAMLlocal1(rv);
	pcap_t *handle_ = pcap_t_ptr_val(handle);
	int cnt_ = Int_val(cnt);
	u_char *user_ = (u_char *)String_val(user);
	int v = pcap_loop(handle_, cnt_, ppp_pcap_handler, user_);
	rv = Val_int(v);
	CAMLreturn(rv);
}
