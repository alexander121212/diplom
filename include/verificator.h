struct verification_struct {
	long 		vrf_addr;
	size_t 		vrf_size;
};


#if defined(POSIX_BUILD)
struct verificator_verify_struct {
	union {
		struct  {
			long 		vrf_addr;
			size_t 		vrf_size;
		};
		struct verification_struct vs;
	};
	unsigned short hash;
};

struct verificator_get_diff_struct {
	union {
		struct  {
			long 		vrf_addr;
			size_t 		vrf_size;
		};
		struct verification_struct vs;
	};
	void *vrd_code;
};

struct verificator_restore_struct {
	union {
		struct  {
			long 		vrf_addr;
			size_t 		vrf_size;
		};
		struct verification_struct vs;
	};
	void *vrr_code;
};

#else
struct verificator_verify_struct {
	struct verification_struct vs;
	unsigned short hash;
};

struct verificator_get_diff_struct {
	struct verification_struct vs;
	void	 __user *vrd_code;
};

struct verificator_restore_struct {
	struct verification_struct vs;
	void	 __user *vrr_code;
};
#endif


#define VERIFICATOR_VERIFY_CODE _IOW('L', 0, struct verificator_verify_struct *)
#define VERIFICATOR_GET_DIFF 	_IOW('L', 1, struct verificator_get_diff_struct *)
#define VERIFICATOR_RESTORE 	_IOW('L', 2, struct verificator_restore_struct *)
