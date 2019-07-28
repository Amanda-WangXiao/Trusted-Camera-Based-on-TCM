dirs= create_key ekpub_send ekpub_store pik_client pik_casign pikcert_verify pikcert_store key_check localkey_gen remotekey_gen remotekey_send uuid_symm_crypt sessionkey_switch
all:
	$(foreach N,$(dirs),make -C $(N) || exit "$$?";)
clean:
	rm -f ../plugin/*.so ../plugin/*.cfg
	$(foreach N,$(dirs),make clean -C $(N);)
	rm -f *~


