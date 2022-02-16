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
}
