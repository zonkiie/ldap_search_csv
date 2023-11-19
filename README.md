# ldap_search_csv
A tool to get ldap search results as Multi Value csv

Sources are partly from
[https://docs.oracle.com/cd/E19957-01/817-6707/index.html](https://docs.oracle.com/cd/E19957-01/817-6707/index.html),
[https://wiki.mozilla.org/Mozilla_LDAP_SDK_Programmer%27s_Guide/Searching_the_Directory_With_LDAP_C_SDK](https://wiki.mozilla.org/Mozilla_LDAP_SDK_Programmer%27s_Guide/Searching_the_Directory_With_LDAP_C_SDK)

Read Schema Information:
[https://wiki.mozilla.org/Mozilla_LDAP_SDK_Programmer%27s_Guide/Getting_Server_Information_With_LDAP_C_SDK](https://wiki.mozilla.org/Mozilla_LDAP_SDK_Programmer%27s_Guide/Getting_Server_Information_With_LDAP_C_SDK)

Needed libs:
-libsasl2-dev (for ldap cleanup reasons)
-libldap2-dev

Fetch LDAP Structure

    BASEPARAMS="-H ldap://${HOSTNAME} -D ${USERNAME} -w ${PASSWORD}"
    SEARCHBASE="cn=subschema"
    FILTER="(objectClass=subschema)"
    FETCHATTRIBUTES="objectclasses attributetypes subschemasubentry"
    ldapsearch ${BASEPARAMS} -s base -b ${SEARCHBASE} ${FILTER} ${FETCHATTRIBUTES}
