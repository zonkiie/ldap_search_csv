#ifndef __dynamic_loading__
#define __dynamic_loading__

int (*ldap_simple_bind_s)(LDAP *ld, const char *who, const char *passwd);
int(*ldap_sasl_bind_s)(LDAP *ld, const char *dn, const char *mechanism,  struct berval *cred, LDAPControl *sctrls[], LDAPControl *cctrls[], struct berval **servercredp);
int (*ldap_unbind_ext_s)(LDAP *ld, LDAPControl *sctrls[], LDAPControl *cctrls[]);
int(*ldap_msgfree)( LDAPMessage *msg );
int(*ldap_result)( LDAP *ld, int msgid, int all, struct timeval *timeout, LDAPMessage **result );
int(*ldap_search_ext)( LDAP *ld, char *base, int scope, char *filter, char *attrs[], int attrsonly, LDAPControl **serverctrls, LDAPControl **clientctrls, struct timeval *timeout, int sizelimit, int *msgidp );
char*(*ldap_first_attribute)(LDAP *ld, LDAPMessage *entry, BerElement **berptr);
char*(*ldap_next_attribute)(LDAP *ld, LDAPMessage *entry, BerElement *ber);
void(*ldap_memfree)(void* p);
int(*ldap_initialize)(LDAP **ldp, char *uri);
int(*ldap_set_option)(LDAP *ld, int option, const void *invalue);
char*(*ldap_err2string)(int err);
char*(*ldap_get_dn)(LDAP *ld, LDAPMessage *entry);
struct berval **(*ldap_get_values_len)(LDAP *ld, LDAPMessage *entry, char *attr);
int(*ldap_parse_reference)(LDAP *ld, LDAPMessage *reference, char ***referralsp, LDAPControl ***serverctrlsp, int freeit );
int(*ldap_parse_result)(LDAP *ld, LDAPMessage *result, int *errcodep, char **matcheddnp, char **errmsgp, char ***referralsp, LDAPControl ***serverctrlsp, int freeit);
void (*ber_free)(BerElement *ber, int freebuf);
void (*ber_bvfree)(struct berval *bv);
struct berval *(*ber_bvstrdup)(const char *str);
void (*ber_bvecfree)(struct berval **bvec);
extern void *dlhandle;
extern char *ldap_lib_path;

void load_dynfunctions();
void cleanup_ldap_dynfunctions();
void init_ldap_dynfunctions();


#endif
