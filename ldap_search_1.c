#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <ldap.h>

/* Change these as needed. */

//https://www.forumsys.com/tutorials/integration-how-to/ldap/online-ldap-test-server/
//https://git.openldap.org/openldap/openldap/-/tree/master/tests/progs
// #define HOSTNAME "localhost"
#define HOSTNAME "ldap.forumsys.com"

#define PORTNUMBER LDAP_PORT

#define BASEDN "ou=mathematicians,dc=example,dc=com"

#define SCOPE LDAP_SCOPE_SUBTREE

#define FILTER "(objectClass=*)"
// https://gist.github.com/syzdek/1459007/31d8fdf197655c8ff001c27b4c1085fb728652f9

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

#define _cleanup_cstr_ __attribute((cleanup(free_cstr)))

int main( int argc, char **argv )

{

	LDAP *ld;

	LDAPMessage *res, *msg;

	LDAPControl **serverctrls;

	BerElement *ber;

	char *a, *dn, *matched_msg = NULL, *error_msg = NULL;
	
	char uri[256];
	sprintf(uri, "ldap://%s:%d", HOSTNAME, PORTNUMBER);

	char **vals, **referrals;

	int version, i, rc, parse_rc, msgtype, num_entries = 0, num_refs = 0;

	/* Get a handle to an LDAP connection. */
	
	if((rc = ldap_initialize(&ld, uri)) != LDAP_SUCCESS)
	{
		fprintf( stderr, "ldap_set_option: %s\n", ldap_err2string( rc ) );

		return( 1 );
	}

	/*if ( (ld = ldap_init( HOSTNAME, PORTNUMBER )) == NULL ) {

		perror( "ldap_init" );

		return( 1 );

	}*/

	version = LDAP_VERSION3;

	if ( ( rc = ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &version ) ) != LDAP_SUCCESS ) {

		//rc = ldap_get_lderrno( ld, NULL, NULL );

		fprintf( stderr, "ldap_set_option: %s\n", ldap_err2string( rc ) );

		ldap_unbind_ext( ld , NULL, NULL);

		return( 1 );

	}

	/* Bind to the server anonymously. */

	rc = ldap_simple_bind_s( ld, NULL, NULL );
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

		ldap_unbind_ext( ld , NULL, NULL);

		return( 1 );

	}
	
	fprintf(stderr, "Bind successfull.\n");
	fflush(stderr);

	/* Perform the search operation. */

	rc = ldap_search_ext_s( ld, BASEDN, SCOPE, FILTER, NULL, 0, NULL, NULL, NULL, LDAP_NO_LIMIT, &res );

	if ( rc != LDAP_SUCCESS ) {

		fprintf( stderr, "ldap_search_ext_s: %s\n", ldap_err2string( rc ) );

		if ( error_msg != NULL && *error_msg != '\0' ) {

			fprintf( stderr, "%s\n", error_msg );

		}

		if ( matched_msg != NULL && *matched_msg != '\0' ) {

			fprintf( stderr, "Part of the DN that matches an existing entry: %s\n", matched_msg );

		}

		ldap_unbind_ext( ld , NULL, NULL);

		return( 1 );

	}

	num_entries = ldap_count_entries( ld, res );

	num_refs = ldap_count_references( ld, res );

	/* Iterate through the results. An LDAPMessage structure sent back from a search operation can contain either an entry found by the search, a search reference, or the final result of the search operation. */

	for ( msg = ldap_first_message( ld, res ); msg != NULL; msg = ldap_next_message( ld, msg ) ) {

		/* Determine what type of message was sent from the server. */

		msgtype = ldap_msgtype( msg );

		switch( msgtype ) {

		/* If the result was an entry found by the search, get and print the attributes and values of the entry. */

		case LDAP_RES_SEARCH_ENTRY:

		/* Get and print the DN of the entry. */

		if (( dn = ldap_get_dn( ld, res )) != NULL ) {

			printf( "dn: %s\n", dn );

			ldap_memfree( dn );

		}

		/* Iterate through each attribute in the entry. */

		for ( a = ldap_first_attribute( ld, res, &ber ); a != NULL; a = ldap_next_attribute( ld, res, ber ) ) {

			/* Get and print all values for each attribute. */

			if (( vals = ldap_get_values( ld, res, a )) != NULL ) {

				for ( i = 0; vals[ i ] != NULL; i++ ) {

					printf( "%s: %s\n", a, vals[ i ] );

				}

				ldap_value_free( vals );

			}

			ldap_memfree( a );

		}

		if ( ber != NULL ) {

			ber_free( ber, 0 );

		}

		printf( "\n" );

		break;

		case LDAP_RES_SEARCH_REFERENCE:

		/* The server sent a search reference encountered during the search operation. */

		/* Parse the result and print the search references. Ideally, rather than print them out, you would follow the references. */

		parse_rc = ldap_parse_reference( ld, msg, &referrals, NULL, 0 );

		if ( parse_rc != LDAP_SUCCESS ) {

			fprintf( stderr, "ldap_parse_result: %s\n", ldap_err2string( parse_rc ) );

			ldap_unbind_ext( ld , NULL, NULL);

			return( 1 );

		}

		if ( referrals != NULL ) {

			for ( i = 0; referrals[ i ] != NULL; i++ ) {

				printf( "Search reference: %s\n\n", referrals[ i ] );

			}

			ldap_value_free( referrals );

		}

		break;

		case LDAP_RES_SEARCH_RESULT:

		/* Parse the final result received from the server. Note the last argument is a non-zero value, which indicates that the LDAPMessage structure will be freed when done. (No need to call ldap_msgfree().) */

		parse_rc = ldap_parse_result( ld, msg, &rc, &matched_msg, &error_msg, NULL, &serverctrls, 0 );

		if ( parse_rc != LDAP_SUCCESS ) {

			fprintf( stderr, "ldap_parse_result: %s\n", ldap_err2string( parse_rc ) );

			ldap_unbind_ext( ld , NULL, NULL);

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

			printf( "Search completed successfully.\n"

				"Entries found: %d\n"

				"Search references returned: %d\n",

				num_entries, num_refs );

			}

			break;

			default:

			break;

		}

	}

	/* Disconnect when done. */

	ldap_unbind_ext( ld , NULL, NULL);

	return( 0 );

}

