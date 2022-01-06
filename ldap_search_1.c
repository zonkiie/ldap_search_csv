#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <malloc.h>
#include <search.h>
#include <ldap.h>

/* Change these as needed. */

//https://www.forumsys.com/tutorials/integration-how-to/ldap/online-ldap-test-server/
//https://git.openldap.org/openldap/openldap/-/tree/master/tests/progs
// #define HOSTNAME "localhost"
#define HOSTNAME "ldap.forumsys.com"

#define PORTNUMBER LDAP_PORT

#define BASEDN "ou=mathematicians,dc=example,dc=com"

#define FILTER "(objectClass=*)"
// https://gist.github.com/syzdek/1459007/31d8fdf197655c8ff001c27b4c1085fb728652f9

#define LF "\n"

#define _cleanup_cstr_ __attribute((cleanup(free_cstr)))
#define _cleanup_ldap_ __attribute((cleanup(free_ldap)))
#define _cleanup_ldap_message_ __attribute((cleanup(free_ldap_message)))
#define _cleanup_ldap_ber_ __attribute((cleanup(free_ber)))
#define _cleanup_file_ __attribute((cleanup(free_file)))
#define _cleanup_carr_ __attribute((cleanup(free_carr_n)))

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
}

void free_ldap_message(LDAPMessage **message)
{
	if(*message == NULL) return;
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
	ber_free(*ber);
	*ber = NULL;
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


int main( int argc, char **argv )
{
	int port = LDAP_PORT, option_index = 0, c = 0, scope = -1;
	// https://stackoverflow.com/questions/59462003/getopt-long-using-flag-struct-member
	static int show_help = 0;
	
	static int print_header = false;
	
	static int no_output = false;
	
	static int debug = false;
	
	bool first_in_row = false;
	
	int version, rc, parse_rc, msgtype, num_entries = 0, num_refs = 0;

	_cleanup_ldap_ LDAP *ld = NULL;

	_cleanup_ldap_message_ LDAPMessage *res = NULL, *msg = NULL;

	LDAPControl **serverctrls;

	BerElement *ber;
	
	_cleanup_cstr_ char *username = NULL;
	_cleanup_cstr_ char *password = NULL;
	_cleanup_cstr_ char *hostname = NULL;
	_cleanup_cstr_ char *basedn = NULL;
	_cleanup_cstr_ char *filter = NULL;
	_cleanup_cstr_ char *configfile = NULL;
	_cleanup_cstr_ char *array_delimiter = NULL;
	_cleanup_cstr_ char *attribute_delimiter = NULL;
	_cleanup_cstr_ char *attributes = NULL;
	
	_cleanup_carr_ char **attributes_array = NULL;
	
	size_t size;
	_cleanup_cstr_ char *buf;
	
	_cleanup_file_ FILE *stream = open_memstream (&buf, &size);
	

	char *dn, *matched_msg = NULL, *error_msg = NULL;
	
	char uri[256];

	char **vals, **referrals;
	
	while(1)
	{
		static struct option long_options[] = {
			{"help", no_argument, &show_help, 1},
			{"debug", no_argument, &debug, 1},
			{"no_output", no_argument, &no_output, 1},
			{"port", required_argument, 0, 0},
			{"hostname", required_argument, 0, 0},
			{"username", required_argument, 0, 0},
			{"password", required_argument, 0, 0},
			{"basedn", required_argument, 0, 0},
			{"filter", required_argument, 0, 0},
			{"scope", required_argument, 0, 0},
			{"array_delimiter", required_argument, 0, 0},
			{"attribute_delimiter", required_argument, 0, 0},
			{"attributes", required_argument, 0, 0},
			{"configfile", required_argument, 0, 0},
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
				if(!strcmp(oname, "username")) username = strdup(optarg);
				if(!strcmp(oname, "password")) password = strdup(optarg);
				if(!strcmp(oname, "basedn")) basedn = strdup(optarg);
				if(!strcmp(oname, "filter")) filter = strdup(optarg);
				if(!strcmp(oname, "array_delimiter")) array_delimiter = strdup(optarg);
				if(!strcmp(oname, "attribute_delimiter")) attribute_delimiter = strdup(optarg);
				if(!strcmp(oname, "attributes")) attributes = strdup(optarg);
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
		puts("--basedn=<basedn>: use base dn <basedn>");
		puts("--print_header: print header of column");
		puts("--debug: print debug messages");
		puts("--no_output: print no output (Usable for debugging)");
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
	if(array_delimiter == NULL) array_delimiter = strdup("|");
	if(attribute_delimiter == NULL) attribute_delimiter = strdup("\t");
	_cleanup_cstr_ char * quoted_array_delimiter;
	_cleanup_cstr_ char * quoted_attribute_delimiter;
	asprintf(&quoted_array_delimiter, "\\%s", array_delimiter);
	asprintf(&quoted_attribute_delimiter, "\\%s", attribute_delimiter);
	
	if(attributes)
	{
		str_split(&attributes_array, attributes, ",");
	}
	
	sprintf(uri, "ldap://%s:%d", hostname, port);
	
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

	/* Bind to the server anonymously. */

	rc = ldap_simple_bind_s( ld, username, password );
	//rc = ldap_sasl_bind_s( ld, NULL, NULL , NULL, NULL, NULL, NULL);

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
	
	/* Perform the search operation. */

	rc = ldap_search_ext_s( ld, basedn, scope, filter, attributes_array, 0, NULL, NULL, NULL, LDAP_NO_LIMIT, &res );

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

	num_entries = ldap_count_entries( ld, res );

	num_refs = ldap_count_references( ld, res );

	/* Iterate through the results. An LDAPMessage structure sent back from a search operation can contain either an entry found by the search, a search reference, or the final result of the search operation. */

	for ( msg = ldap_first_message( ld, res ); msg != NULL; msg = ldap_next_message( ld, msg ) ) {
	//for ( msg = ldap_first_entry( ld, res ); msg != NULL; msg = ldap_next_entry( ld, msg ) ) {

		/* Determine what type of message was sent from the server. */

		msgtype = ldap_msgtype( msg );

		switch( msgtype ) {

			/* If the result was an entry found by the search, get and print the attributes and values of the entry. */

			case LDAP_RES_SEARCH_ENTRY:
				if(debug) fputs("LDAP_RES_SEARCH_ENTRY\n", stderr);

				/* Get and print the DN of the entry. */

				if (debug && ( dn = ldap_get_dn( ld, res )) != NULL) {

					fprintf(stderr, "dn: %s\n", dn );

					ldap_memfree( dn );

				}

				/* Iterate through each attribute in the entry. */
				first_in_row = true;
				bool header_printed = false;
				if(!header_printed && print_header)
				{
					for (char *a = ldap_first_attribute( ld, res, &ber ); a != NULL; a = ldap_next_attribute( ld, res, ber ) ) {
						if(first_in_row) first_in_row = false;
						else fputs(attribute_delimiter, stream);
						fputs(a, stream);
						ldap_memfree( a );
					}
					fputs(LF, stream);
					header_printed = true;
					ber_free( ber, 0 );
				}
				
				first_in_row = true;
				for (char *a = ldap_first_attribute( ld, res, &ber ); a != NULL; a = ldap_next_attribute( ld, res, ber ) ) {	
					if(first_in_row) first_in_row = false;
					else fputs(attribute_delimiter, stream);
					/* Get and print all values for each attribute. */
					//fprintf(stderr, "a: %s\n", a);
					struct berval **vals = NULL;
					if((vals = ldap_get_values_len(ld, res, a)) != NULL)
					{
						bool first_in_array = true;
						for ( int vi = 0; vals[ vi ] != NULL; vi++ ) {

							//printf( "%s: %s\n", a, vals[ vi ]->bv_val );
							if(first_in_array == true) first_in_array = false;
							//else fputs(array_delimiter, stream);
							else fputs(array_delimiter, stream);
							_cleanup_carr_ char ** step = (char**)calloc(5, sizeof(char*));
							step[0] = str_replace(vals[ vi ]->bv_val, array_delimiter, quoted_array_delimiter);
							step[1] = str_replace(step[0], "\"", "\"\"\"\"");
							step[2] = str_replace(step[1], "\n", "\\n");
							step[3] = str_replace(step[2], attribute_delimiter, quoted_attribute_delimiter);
							fputs(step[3], stream);
							//fputs(vals[ vi ]->bv_val, stream);

						}
						ber_bvecfree(vals);
					}
					
					ldap_memfree( a );

				}

				if ( ber != NULL ) {

					ber_free( ber, 0 );

				}

				//printf( "\n" );
				fputs(LF, stream);

				break;

			case LDAP_RES_SEARCH_REFERENCE:
				if(debug) fputs("LDAP_RES_SEARCH_REFERENCE", stderr);

				/* The server sent a search reference encountered during the search operation. */

				/* Parse the result and print the search references. Ideally, rather than print them out, you would follow the references. */

				parse_rc = ldap_parse_reference( ld, msg, &referrals, NULL, 0 );

				if ( parse_rc != LDAP_SUCCESS ) {

					fprintf( stderr, "ldap_parse_result: %s\n", ldap_err2string( parse_rc ) );

					return( 1 );

				}

				if ( referrals != NULL ) {

					for ( int ri = 0; referrals[ ri ] != NULL; ri++ ) {

						printf( "Search reference: %s\n\n", referrals[ ri ] );

					}

					ldap_value_free( referrals );

				}

				break;

			case LDAP_RES_SEARCH_RESULT:
				if(debug) fputs("LDAP_RES_SEARCH_RESULT\n", stderr);

				/* Parse the final result received from the server. Note the last argument is a non-zero value, which indicates that the LDAPMessage structure will be freed when done. (No need to call ldap_msgfree().) */

				parse_rc = ldap_parse_result( ld, msg, &rc, &matched_msg, &error_msg, NULL, &serverctrls, 0 );

				if ( parse_rc != LDAP_SUCCESS ) {

					fprintf( stderr, "ldap_parse_result: %s\n", ldap_err2string( parse_rc ) );

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

				/*printf( "Search completed successfully.\n"

					"Entries found: %d\n"

					"Search references returned: %d\n",

					num_entries, num_refs );*/

				}

				break;

			default:
				fputs("DEFAULT\n", stderr);

				break;

		}

	}
	fflush(stream);
	if(!no_output) puts(buf);

	/* Disconnect when done. */

	return( 0 );

}

