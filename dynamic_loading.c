#include <dynamic_loading.h>

void *dlhandle;
char *ldap_lib_path;

void load_dynfunctions()
{
	dlhandle = dlopen(ldap_lib_path, RTLD_LAZY);
	atexit(cleanup_ldap_dynfunctions);
}
