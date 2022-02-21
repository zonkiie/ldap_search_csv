#include <dynamic_loading.h>

void *dlhandle;
char *ldap_lib_path;

void cleanup_ldap_dynfunctions()
{
	dlclose(dlhandle);
}

void load_dynfunctions()
{
	dlhandle = dlopen(ldap_lib_path, RTLD_LAZY);
	atexit(cleanup_ldap_dynfunctions);
}

void init_ldap_dynfunctions()
{
	ldap_simple_bind_s = (int(*)(LDAP *, const char *, const char *)) dlsym(dlhandle, "ldap_simple_bind_s");
	ldap_sasl_bind_s = (int(*)(LDAP *, const char *, const char *,  struct berval *, LDAPControl **, LDAPControl **, struct berval **)) dlsym(dlhandle, "ldap_sasl_bind_s");
	ldap_unbind_ext_s = (int(*)(LDAP *ld, LDAPControl *sctrls[], LDAPControl *cctrls[])) dlsym(dlhandle, "ldap_unbind_ext_s");
	ldap_msgfree = (int(*)( LDAPMessage *msg )) dlsym(dlhandle, "ldap_msgfree");
	ldap_result = (int(*)( LDAP *ld, int msgid, int all, struct timeval *timeout, LDAPMessage **result )) dlsym(dlhandle, "ldap_result");
	ldap_search_ext = (int(*)( LDAP *ld, char *base, int scope, char *filter, char *attrs[], int attrsonly, LDAPControl **serverctrls, LDAPControl **clientctrls, struct timeval *timeout, int sizelimit, int *msgidp )) dlsym(dlhandle, "ldap_search_ext");
	ldap_first_attribute = (char*(*)(LDAP *ld, LDAPMessage *entry, BerElement **berptr)) dlsym(dlhandle, "ldap_first_attribute");
	ldap_next_attribute = (char*(*)(LDAP *ld, LDAPMessage *entry, BerElement *ber)) dlsym(dlhandle, "ldap_next_attribute");
	ldap_memfree = (void(*)(void* p)) dlsym(dlhandle, "ldap_memfree");
	ldap_initialize = (int(*)(LDAP **ldp, char *uri)) dlsym(dlhandle, "ldap_initialize");
	ldap_set_option = int(*)(LDAP *ld, int option, const void *invalue)) dlsym(dlhandle, "ldap_set_option");
	ldap_err2string = (char*(*)(int err)) dlsym(dlhandle, "ldap_err2string");
	ldap_get_dn = (char*(*)(LDAP *ld, LDAPMessage *entry)) dlsym(dlhandle, "ldap_get_dn");
	ldap_get_values_len = (struct berval **(*)(LDAP *ld, LDAPMessage *entry, char *attr)) dlsym(dlhandle, "ldap_get_values_len");
	ldap_parse_reference = (int(*)(LDAP *ld, LDAPMessage *reference, char ***referralsp, LDAPControl ***serverctrlsp, int freeit )) dlsym(dlhandle, "ldap_parse_reference");
	ldap_parse_result = (int(*)(LDAP *ld, LDAPMessage *result, int *errcodep, char **matcheddnp, char **errmsgp, char ***referralsp, LDAPControl ***serverctrlsp, int freeit)) dlsym(dlhandle, "ldap_parse_result");
	ber_free = (void (*)(BerElement *ber, int freebuf)) dlsym(dlhandle, "ber_free");
	ber_bvfree = (void (*)(struct berval *bv)) dlsym(dlhandle, "ber_bvfree");
	ber_bvstrdup = (struct berval *(*)(const char *str)) dlsym(dlhandle, "ber_bvstrdup");
	ber_bvecfree = (void (*)(struct berval **bvec)) dlsym(dlhandle, "ber_bvecfree");
}
