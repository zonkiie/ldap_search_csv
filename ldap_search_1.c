#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <malloc.h>
#include <search.h>
#include <ldap.h>
#include <sasl/sasl.h>

/* Change these as needed. */

//https://www.forumsys.com/tutorials/integration-how-to/ldap/online-ldap-test-server/
//https://git.openldap.org/openldap/openldap/-/tree/master/tests/progs
// #define HOSTNAME "localhost"
#define HOSTNAME "ldap.forumsys.com"

#define PORTNUMBER LDAP_PORT
#define PORTNUMBER_TLS LDAPS_PORT

#define BASEDN "ou=mathematicians,dc=example,dc=com"

#define FILTER "(objectClass=*)"
// https://gist.github.com/syzdek/1459007/31d8fdf197655c8ff001c27b4c1085fb728652f9

#define LF "\n"

#define DEFAULT_NULL "(null)"
#define DEFAULT_TRIM_CHARS " \r\n"

#define _cleanup_cstr_ __attribute((cleanup(free_cstr)))
#define _cleanup_ldap_ __attribute((cleanup(free_ldap)))
#define _cleanup_ldap_message_ __attribute((cleanup(free_ldap_message)))
#define _cleanup_ldap_ber_ __attribute((cleanup(free_ber)))
#define _cleanup_file_ __attribute((cleanup(free_file)))
#define _cleanup_carr_ __attribute((cleanup(free_carr_n)))
#define _cleanup_berval_ __attribute((cleanup(free_berval)))
#define _cleanup_quote_strings_ __attribute((cleanup(free_quote_strings)))

struct         timeval  zerotime = {.tv_sec = 0L, .tv_usec = 0L};

typedef struct {
	char * attribute_delimiter;
	char * array_delimiter;
	char * null_string;
	char * tab_string;
	char * linefeed_quot;
	char * quotation_escape;
} quote_strings;

void free_cstr(char ** str)
{
	if(*str == NULL) return;
	free(*str);
	*str = NULL;
}

void reassign_cstr(char **str, const char * value)
{
	free_cstr(str);
	*str = strdup(value);
}

void free_ldap(LDAP **ldap)
{
	if(*ldap == NULL) return;
	ldap_unbind_ext_s( *ldap , NULL, NULL);
	*ldap = NULL;
	sasl_done();
}

void free_ldap_message(LDAPMessage **message)
{
	if(*message == NULL || message == NULL) return;
	ldap_msgfree(*message);
	*message = NULL;
}

int get_carr_size(char ** carr)
{
	if(carr == NULL) return 0;
    int i = 0;
    for(; carr[i] != NULL; i++);
    return i;
}

/** Free c array strings and null memory */
void free_carr_n(char ***carr)
{
    if(carr == NULL || *carr == NULL) return;
	int size = get_carr_size(*carr);
	for(int i = size - 1; i >= 0; i--) 
	{
		free((*carr)[i]);
		(*carr)[i] = NULL;
	}
	free(*carr);
	*carr = NULL;
}

void free_ber(BerElement **ber)
{
	if(ber == NULL || *ber == NULL) return;
	ber_free(*ber, 0);
	*ber = NULL;
}

void free_berval(struct berval **bval)
{
	if(bval == NULL || *bval == NULL) return;
	ber_bvfree(*bval);
	*bval = NULL;
}

int substr_count(char *str, char *substr)
{
	if(str == NULL || !strcmp(str, "")) return 0;
	char * found = str;
	int count = 0;
	while(found = strstr(found + strlen(substr), substr)) count++;
	return count;
}

int str_split(char ***dest, char *str, char *separator)
{
	int el_count = substr_count(str, separator) + 1;
	*dest = (char**)malloc((el_count + 1) * sizeof(char*));
	memset((*dest), 0, (el_count + 1));
	char *walker = strstr(str, separator), *trailer = str;
	int index = 0;
	while(true)
	{
		if(walker == NULL)
		{
			(*dest)[index++] = strdup(trailer);
			break;
		}
		(*dest)[index++] = strndup(trailer, walker - trailer);
		trailer = walker + strlen(separator);
		walker = strstr(trailer, separator);
	}
	(*dest)[index] = NULL;
	return index;
}

void free_file(FILE** file)
{
	if(*file == NULL) return;
	fflush(*file);
	fclose(*file);
	*file = NULL;
}

void free_quote_strings(quote_strings ** quot)
{
	if(quot == NULL || *quot == NULL) return;
	if((*quot)->attribute_delimiter) free_cstr(&((*quot)->attribute_delimiter));
	if((*quot)->array_delimiter) free_cstr(&((*quot)->array_delimiter));
	if((*quot)->null_string) free_cstr(&((*quot)->null_string));
	if((*quot)->tab_string) free_cstr(&((*quot)->tab_string));
	if((*quot)->linefeed_quot) free_cstr(&((*quot)->linefeed_quot));
	if((*quot)->quotation_escape) free_cstr(&((*quot)->quotation_escape));
	free(*quot);
	(*quot) = NULL;
}

char * str_replace(const char *str, const char *search, const char *replace)
{
	if(str == NULL) return NULL;
	if(!strcmp(str, "")) return strdup("");
	char *retstr = strdup(""), *walker, *trailer = (char*)str;
	while(true)
	{
		if((walker = strstr(trailer, search)) == NULL)
		{
			_cleanup_cstr_ char * savestr = strdup(retstr);
			free(retstr);
			asprintf(&retstr, "%s%s", savestr, trailer);
			break;
		}
		_cleanup_cstr_ char * part = strndup(trailer, walker - trailer);
		_cleanup_cstr_ char * saveptr = strdup(retstr);
		free(retstr);
		asprintf(&retstr, "%s%s%s", saveptr, part, replace);
		trailer = walker + strlen(search);
	}
	return retstr;
}

char * quote_string(const char *str, quote_strings * quot)
{
	_cleanup_cstr_ char * quoted_array_delimiter;
	_cleanup_cstr_ char * quoted_attribute_delimiter;
	asprintf(&quoted_array_delimiter, "\\%s", quot->array_delimiter);
	asprintf(&quoted_attribute_delimiter, "\\%s", quot->attribute_delimiter);
	
	_cleanup_carr_ char ** step = (char**)calloc(10, sizeof(char*));
	step[0] = str_replace(str, quot->array_delimiter, quoted_array_delimiter);
	step[1] = str_replace(step[0], "\"", "\"\"\"\"");
	step[2] = str_replace(step[1], "\n", "\\n");
	step[3] = str_replace(step[2], "\r", "\\r");
	step[4] = str_replace(step[3], quot->attribute_delimiter, quoted_attribute_delimiter);
	return strdup(step[4]);
}

bool in_array(char ** array, char * value)
{
	for(int i = 0; array[i] != NULL; i++)
	{
		if(!strcmp(array[i], value)) return true;
	}
	return false;
}

/// returns true if value is added, false if value is already in array
/// array must be big enough that one further value can be added.
/// value is copied to the new position.
bool add_to_unique_array(char *** array, char * value)
{
	int i = 0;
	for(; (*array)[i] != NULL; i++)
	{
		if(!strcmp((*array)[i], value)) return false;
	}
	(*array)[i] = strdup(value);
	return true;
}

char ** get_attributes_from_ldap(LDAP *ld, char * basedn, int scope, char * filter)
{
	int finished = 0, msgid = 0, i = 0;
	
	char **attributes_array = (char**)calloc(sizeof(char*), 512);
	_cleanup_cstr_ char *matched_msg = NULL, *error_msg = NULL;
	_cleanup_ldap_message_ LDAPMessage *res = NULL;
	BerElement *ber;
	/* Perform the search operation. */
	int rc = ldap_search_ext( ld, basedn, scope, filter, NULL, 1, NULL, NULL, NULL, LDAP_NO_LIMIT, &msgid );

	if ( rc != LDAP_SUCCESS ) {

		//fprintf( stderr, "ldap_search_ext_s: %s\n", ldap_err2string( rc ) );

		if ( error_msg != NULL && *error_msg != '\0' ) {

			fprintf( stderr, "%s\n", error_msg );

		}

		if ( matched_msg != NULL && *matched_msg != '\0' ) {

			fprintf( stderr, "Part of the DN that matches an existing entry: %s\n", matched_msg );

		}

		free_carr_n(&attributes_array);
		return( NULL );
		

	}
	while(!finished)
	{
		rc = ldap_result( ld, msgid, LDAP_MSG_ONE, &zerotime, &res );
		switch( rc ) {
			case -1:
				return( NULL );
			case 0:
				break;
			case LDAP_RES_SEARCH_ENTRY:
				for (char *a = ldap_first_attribute( ld, res, &ber ); a != NULL; a = ldap_next_attribute( ld, res, ber ) ) {
					add_to_unique_array(&attributes_array, a);
					ldap_memfree( a );
				}
				ber_free( ber, 0 );
			case LDAP_RES_SEARCH_RESULT:
				finished = true;
			
		}
	}
	return attributes_array;
}

bool char_charlist(char c, char *charlist)
{
	for(int i = 0; i < strlen(charlist); i++)
	{
		if(charlist[i] == c) return true;
	}
	return false;
}

char *trim(char *string, char *trimchars)
{
	if(!trimchars || strlen(trimchars) == 0) return strdup(string);
	// ltrim
	int start = 0;
	while(char_charlist(string[start], trimchars)) start++;
	// rtrim
	int copylen = strlen(string + start);
	while(copylen > 1 && char_charlist((string + start)[copylen - 1], trimchars)) copylen--;
	return strndup((string + start), copylen);
}


int main( int argc, char **argv )
{
	int port = LDAP_PORT, option_index = 0, c = 0, scope = -1;
	// https://stackoverflow.com/questions/59462003/getopt-long-using-flag-struct-member
	static int show_help = 0;
	
	static int print_header = false;
	
	static int no_output = false;
	
	static int debug = false;
	
	static int use_sasl = false;
	
	static int attributes_only = false;
	
	static int print_referals = false;
	
	static int trim_strings = false;
	
	bool first_in_row = false, header_printed = false;
	
	int version, msgid, rc, parse_rc, finished = 0, msgtype, num_entries = 0, num_refs = 0;

	_cleanup_ldap_ LDAP *ld = NULL;

	_cleanup_ldap_message_ LDAPMessage *res = NULL;
	
	LDAPMessage *msg = NULL;

	LDAPControl **serverctrls;

	BerElement *ber;
	
	_cleanup_cstr_ char *username = NULL;
	_cleanup_cstr_ char *password = NULL;
	_cleanup_cstr_ char *hostname = NULL;
	_cleanup_cstr_ char *basedn = NULL;
	_cleanup_cstr_ char *filter = NULL;
	_cleanup_cstr_ char *configfile = NULL;
	_cleanup_cstr_ char *attributes = NULL;
	_cleanup_cstr_ char *uri = NULL;
	_cleanup_cstr_ char *trim_chars = NULL;
	_cleanup_berval_ struct berval *berval_password = NULL;
	
	_cleanup_quote_strings_ quote_strings *quot_str = (quote_strings*)calloc(1, sizeof(quote_strings));
	if(quot_str == NULL) abort();
	
	_cleanup_carr_ char **attributes_array = NULL;
	
	size_t size;
	_cleanup_cstr_ char *buf;
	
	_cleanup_file_ FILE *stream = open_memstream (&buf, &size);
	

	char *dn, *matched_msg = NULL, *error_msg = NULL;
	
	while(1)
	{
		static struct option long_options[] = {
			{"help", no_argument, &show_help, 1},
			{"debug", no_argument, &debug, 1},
			{"no_output", no_argument, &no_output, 1},
			{"use_sasl", no_argument, &use_sasl, 1},
			{"attributes_only", no_argument, &attributes_only, 1},
			{"print_referals", no_argument, &print_referals, 1},
			{"port", required_argument, 0, 0},
			{"hostname", required_argument, 0, 0},
			{"nullstring", required_argument, 0, 0},
			{"uri", required_argument, 0, 0},
			{"username", required_argument, 0, 0},
			{"password", required_argument, 0, 0},
			{"basedn", required_argument, 0, 0},
			{"filter", required_argument, 0, 0},
			{"scope", required_argument, 0, 0},
			{"array_delimiter", required_argument, 0, 0},
			{"attribute_delimiter", required_argument, 0, 0},
			{"attributes", required_argument, 0, 0},
			{"configfile", required_argument, 0, 0},
			{"trim_chars", required_argument, 0, 0},
			{"trim_strings", no_argument, &trim_strings, 1},
			{"print_header", no_argument, &print_header, 1},
			{0, 0, 0, 0},
		};
		c = getopt_long (argc, argv, "hc:", long_options, &option_index);
		if(c == -1) break;
		switch(c)
		{
			case 0:
			{
				char* oname = (char*)long_options[option_index].name;
				if(!strcmp(oname, "port")) port = atoi(optarg);
				if(!strcmp(oname, "hostname")) hostname = strdup(optarg);
				if(!strcmp(oname, "uri")) uri = strdup(optarg);
				if(!strcmp(oname, "username")) username = strdup(optarg);
				if(!strcmp(oname, "password")) password = strdup(optarg);
				if(!strcmp(oname, "basedn")) basedn = strdup(optarg);
				if(!strcmp(oname, "filter")) filter = strdup(optarg);
				if(!strcmp(oname, "nullstring")) quot_str->null_string = strdup(optarg);
				if(!strcmp(oname, "array_delimiter")) quot_str->array_delimiter = strdup(optarg);
				if(!strcmp(oname, "attribute_delimiter")) quot_str->attribute_delimiter = strdup(optarg);
				if(!strcmp(oname, "attributes")) attributes = strdup(optarg);
				if(!strcmp(oname, "trim_chars")) trim_chars = strdup(optarg);
				if(!strcmp(oname, "configfile")) configfile = strdup(optarg);
				if(!strcmp(oname, "scope"))
				{
					if(!strcasecmp(optarg, "LDAP_SCOPE_BASE")) scope = LDAP_SCOPE_BASE;
					else if(!strcasecmp(optarg, "LDAP_SCOPE_ONELEVEL")) scope = LDAP_SCOPE_ONELEVEL;
					else if(!strcasecmp(optarg, "LDAP_SCOPE_SUBTREE")) scope = LDAP_SCOPE_SUBTREE;
					else if(!strcasecmp(optarg, "LDAP_SCOPE_CHILDREN")) scope = LDAP_SCOPE_CHILDREN;
					else abort();
				}
				break;
			}
			case 1:
			{
				break;
			}
			case 'h':
			{
				show_help = 1;
				break;
			}
			case 'c':
			{
				configfile = strdup(optarg);
				break;
			}
			
			default:
				abort();
		}
	}
	if(show_help)
	{
		puts("Command line has priority over Config file!");
		puts("--username=<username>: connect to host with username <username>");
		puts("--password=<password>: connect to host with password <password>");
		puts("--hostname=<hostname>: connect to host <hostname>");
		puts("--port=<port>: connect to port <port>");
		puts("--uri=<uri>: use <uri> as target");
		puts("--basedn=<basedn>: use base dn <basedn>");
		puts("--nullstring=<null>: define nullstring (Default:" DEFAULT_NULL ")");
		puts("--print_header: print header of column");
		puts("--debug: print debug messages");
		puts("--no_output: print no output (Usable for debugging)");
		puts("--use_sasl: use sasl for connection (experimental!)");
		puts("--attributes_only: fetch only attributes, no values");
		puts("--print_referals: print referals if available");
		puts("--trim_strings: trim strings");
		puts("--trim_chars=<chars>: chars to bei used to be trimmed away");
		puts("--filter=<filter>: apply the filter <filter>");
		puts("--scope=<scope>: use one of the scopes: LDAP_SCOPE_BASE, LDAP_SCOPE_ONELEVEL, LDAP_SCOPE_SUBTREE, LDAP_SCOPE_CHILDREN - Important: Give the scope!");
		puts("--array_delimiter=<delimiter>: use the delimiter <delimiter> to separate array entries");
		puts("--attribute_delimiter=<delimiter>: use the delimiter <delimiter> to separate attributes");
		puts("--attributes=<attributes>: csv list of queried attributes");
		exit(0);
	}
	
	//initialize values with default values during testing
	if(hostname == NULL) hostname = strdup(HOSTNAME);
	if(basedn == NULL) basedn = strdup(BASEDN);
	if(filter == NULL) filter = strdup(FILTER);
	if(password != NULL) berval_password = ber_bvstrdup(password);
	if(quot_str->null_string == NULL) quot_str->null_string = strdup(DEFAULT_NULL);
	if(quot_str->array_delimiter == NULL) quot_str->array_delimiter = strdup("|");
	if(quot_str->attribute_delimiter == NULL) quot_str->attribute_delimiter = strdup("\t");
	
	if(attributes)
	{
		str_split(&attributes_array, attributes, ",");
	}
	
	if(!trim_chars && trim_strings) trim_chars = strdup(DEFAULT_TRIM_CHARS);
	
	if(uri == NULL) asprintf(&uri, "ldap://%s:%d", hostname, port);
	
	/* Get a handle to an LDAP connection. */
	
	if((rc = ldap_initialize(&ld, uri)) != LDAP_SUCCESS)
	{
		fprintf( stderr, "ldap_set_option: %s\n", ldap_err2string( rc ) );

		return( 1 );
	}

	version = LDAP_VERSION3;

	if ( ( rc = ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &version ) ) != LDAP_SUCCESS ) {

		//rc = ldap_get_lderrno( ld, NULL, NULL );

		fprintf( stderr, "ldap_set_option: %s\n", ldap_err2string( rc ) );

		return( 1 );

	}

	/* Bind to the server */

	if(!use_sasl) rc = ldap_simple_bind_s( ld, username, password );
	else rc = ldap_sasl_bind_s( ld, username, LDAP_SASL_SIMPLE, berval_password , NULL, NULL, NULL);

	if ( rc != LDAP_SUCCESS ) {

		fprintf( stderr, "ldap_simple_bind_s: %s\n", ldap_err2string( rc ) );

		/*ldap_get_lderrno( ld, &matched_msg, &error_msg );

		if ( error_msg != NULL && *error_msg != '\0' ) {

			fprintf( stderr, "%s\n", error_msg );

		}

		if ( matched_msg != NULL && *matched_msg != '\0' ) {

			fprintf( stderr, "Part of the DN that matches an existing entry: %s\n", matched_msg );

		}*/

		return( 1 );

	}
	
	if(attributes == NULL)
	{
		attributes_array = get_attributes_from_ldap(ld, basedn, scope, filter);
		if(attributes_only)
		{
			for(int i = 0; attributes_array[i] != NULL; i++)
			{
				printf("%s,", attributes_array[i]);
			}
			printf("\n");
			exit(0);
		}
	}

	/* Perform the search operation. */
	rc = ldap_search_ext( ld, basedn, scope, filter, attributes_array, 0, NULL, NULL, NULL, LDAP_NO_LIMIT, &msgid );

	if ( rc != LDAP_SUCCESS ) {

		//fprintf( stderr, "ldap_search_ext_s: %s\n", ldap_err2string( rc ) );

		if ( error_msg != NULL && *error_msg != '\0' ) {

			fprintf( stderr, "%s\n", error_msg );

		}

		if ( matched_msg != NULL && *matched_msg != '\0' ) {

			fprintf( stderr, "Part of the DN that matches an existing entry: %s\n", matched_msg );

		}

		return( 1 );

	}
	while ( !finished )
	{
		rc = ldap_result( ld, msgid, LDAP_MSG_ONE, &zerotime, &res );
		//if(debug) fprintf(stderr, "rc: %d\n", rc);
		
		switch( rc ) {
			case -1:
				fprintf( stderr, "ldap_result: %s\n", ldap_err2string( rc ) );
				return( 1 );
			case 0:
				if(debug) fprintf(stderr, "Line: %d - Break\n", __LINE__);
				break;

			/* If the result was an entry found by the search, get and print the attributes and values of the entry. */

			case LDAP_RES_SEARCH_ENTRY:
				if(debug) fputs("LDAP_RES_SEARCH_ENTRY\n", stderr);
				
				num_entries++;

				/* Get and print the DN of the entry. */

				_cleanup_cstr_ char *entrydn = NULL;
				if((dn = ldap_get_dn(ld, res)) != NULL) {
					entrydn = strdup(dn);
					ldap_memfree(dn);
				}

				if (debug && entrydn != NULL) {

					fprintf(stderr, "dn: %s\n", entrydn );

				}

				/* Iterate through each attribute in the entry. */
				first_in_row = true;
				if(!header_printed && print_header)
				{
					//for (char *a = ldap_first_attribute( ld, res, &ber ); a != NULL; a = ldap_next_attribute( ld, res, ber ) ) {
					for(char ** a = attributes_array; *a != NULL; *a++) {
						if(first_in_row) first_in_row = false;
						else fputs(quot_str->attribute_delimiter, stream);
						fputs(*a, stream);
						//fputs(a, stream);
						//ldap_memfree( a );
					}
					fputs(LF, stream);
					header_printed = true;
					//ber_free( ber, 0 );
				}
				
				first_in_row = true;
				//for (char *a = ldap_first_attribute( ld, res, &ber ); a != NULL; a = ldap_next_attribute( ld, res, ber ) ) {	
				for(char ** a = attributes_array; *a != NULL; *a++) {
					if(first_in_row) first_in_row = false;
					else fputs(quot_str->attribute_delimiter, stream);
					/* Get and print all values for each attribute. */
					//if(debug) fprintf(stderr, "attrib: %s\n", a);
					if(debug) fprintf(stderr, "attrib: %s\n", *a);

					if(!strcasecmp(*a, "dn") && entrydn != NULL)
					{
						_cleanup_cstr_ char *trimmed_str = trim(entrydn, trim_chars);
						_cleanup_cstr_ char *quoted_val = quote_string(trimmed_str, quot_str);
						fprintf(stderr, "quoted val for dn: %s, dn: %s\n", quoted_val, entrydn);
						fputs(quoted_val, stream);
						continue;

					}
					struct berval **vals = NULL;
					
					//if((vals = ldap_get_values_len(ld, res, a)) != NULL)
					if((vals = ldap_get_values_len(ld, res, *a)) != NULL)
					{
						bool first_in_array = true;
						
						if(debug) fprintf(stderr, "ldap_count_values_len(vals): %d\n", ldap_count_values_len(vals));
						if(ldap_count_values_len(vals) == 0)
						{
							if(debug) fprintf(stderr, "Nullstring found! Line: %d", __LINE__);
							fputs(quot_str->null_string, stream);
						}
						else
						{
							for ( int vi = 0; vals[ vi ] != NULL; vi++ ) {

								//printf( "%s: %s\n", a, vals[ vi ]->bv_val );
								if(first_in_array == true) first_in_array = false;
								//else fputs(array_delimiter, stream);
								else fputs(quot_str->array_delimiter, stream);
								if(!strcmp(vals[ vi ]->bv_val, "") && debug) fprintf(stderr, "empty string found in %s!", *a);
								//_cleanup_cstr_ char * quoted_val = quote_string(vals[ vi ]->bv_val, quot_str);
								/*fprintf(stderr, "entry val: %s\n", vals[ vi ]->bv_val);
								if(vals[ vi ]->bv_val == NULL && !strcasecmp(*a, "dn") && entrydn != NULL)
								{
									_cleanup_cstr_ char *trimmed_str = trim(entrydn, trim_chars);
									_cleanup_cstr_ char *quoted_val = quote_string(trimmed_str, quot_str);
									fprintf(stderr, "quoted val for dn: %s, dn: %s\n", quoted_val, entrydn);
									fputs(quoted_val, stream);
									continue;
								}*/
								//_cleanup_cstr_ char *trimmed_str = trim(vals[ vi ]->bv_val, trim_chars);
								_cleanup_cstr_ char *trimmed_str = trim(vals[ vi ]->bv_val, trim_chars);
								_cleanup_cstr_ char *quoted_val = quote_string(trimmed_str, quot_str);
								fputs(quoted_val, stream);
								//fputs(vals[ vi ]->bv_val, stream);

							}
						}
						ber_bvecfree(vals);
					}
					else
					{
						if(debug) fprintf(stderr, "Nullstring found! Line: %d", __LINE__);
						fputs(quot_str->null_string, stream);
					}
					
					//ldap_memfree( a );

				}

				/*if ( ber != NULL ) {

					ber_free( ber, 0 );

				}*/

				//printf( "\n" );
				fputs(LF, stream);
				
				free_ldap_message(&res);

				break;

			case LDAP_RES_SEARCH_REFERENCE:
				if(debug) fputs("LDAP_RES_SEARCH_REFERENCE", stderr);
				
				num_refs++;

				/* The server sent a search reference encountered during the search operation. */

				/* Parse the result and print the search references. Ideally, rather than print them out, you would follow the references. */
				{
					_cleanup_carr_ char **referrals;

					// parse_rc = ldap_parse_reference( ld, res, &referrals, NULL, 0 );
					parse_rc = ldap_parse_reference( ld, res, &referrals, NULL, 1 );

					if ( parse_rc != LDAP_SUCCESS ) {

						fprintf( stderr, "ldap_parse_result: %s\n", ldap_err2string( parse_rc ) );

						return( 1 );

					}

					if ( referrals != NULL ) {

						for ( int ri = 0; referrals[ ri ] != NULL; ri++ ) {

							if(print_referals) printf( "Search reference: %s\n\n", referrals[ ri ] );

						}
					}
				}

				break;

			case LDAP_RES_SEARCH_RESULT:
				if(debug) fputs("LDAP_RES_SEARCH_RESULT\n", stderr);
				finished = 1;

				/* Parse the final result received from the server. Note the last argument is a non-zero value, which indicates that the LDAPMessage structure will be freed when done. (No need to call ldap_msgfree().) */

				//parse_rc = ldap_parse_result( ld, msg, &rc, &matched_msg, &error_msg, NULL, &serverctrls, 0 );
				parse_rc = ldap_parse_result( ld, res, &rc, &matched_msg, &error_msg, NULL, &serverctrls, 0 );

				if ( parse_rc != LDAP_SUCCESS ) {

					fprintf( stderr, "ldap_parse_result: %s\n", ldap_err2string( parse_rc ) );
					free_ldap_message(&res);

					return( 1 );

				}

				/* Check the results of the LDAP search operation. */

				if ( rc != LDAP_SUCCESS ) {

					fprintf( stderr, "ldap_search_ext: %s\n", ldap_err2string( rc ) );

					if ( error_msg != NULL & *error_msg != '\0' ) {

						fprintf( stderr, "%s\n", error_msg );

					}

					if ( matched_msg != NULL && *matched_msg != '\0' ) {

						fprintf( stderr, "Part of the DN that matches an existing entry: %s\n", matched_msg );

					}

				} else {

					if(debug) fprintf(stderr, "Search completed successfully.\n"

						"Entries found: %d\n"

						"Search references returned: %d\n",

						num_entries, num_refs );

				}
				
				free_ldap_message(&res);

				break;

			default:
				fputs("DEFAULT\n", stderr);

				break;

		}

	}
	fflush(stream);
	//if(!no_output) puts(buf);
	//if(!no_output) fwrite(buf, sizeof(char*), size, stdout);
	if(!no_output) printf("%s", buf);

	/* Disconnect when done. */

	return( 0 );

}

