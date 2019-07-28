dirs= key_manage login_client login_test transfer
all:
	$(foreach N,$(dirs),make -C $(N) || exit "$$?";)
clean:
	rm -f ../plugin/*.so ../plugin/*.cfg
	$(foreach N,$(dirs),make clean -C $(N);)
	rm -f *~


