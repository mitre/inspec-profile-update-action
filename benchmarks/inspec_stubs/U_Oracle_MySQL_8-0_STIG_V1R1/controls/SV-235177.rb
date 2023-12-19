control 'SV-235177' do
  title 'The MySQL Database Server 8.0 must prohibit the use of cached authenticators after an organization-defined time period.'
  desc 'If cached authentication information is out-of-date, the validity of the authentication information may be questionable.'
  desc 'check', "Verify that the MySQL is using Kerberos Authentication.  

On the server:
SELECT PLUGIN_NAME, PLUGIN_STATUS
       FROM INFORMATION_SCHEMA.PLUGINS
       WHERE PLUGIN_NAME LIKE '%ldap%';

On the client(s) where Kerberos will authenticate, check how long the ticket is cached.

First check whether Kerberos authentication works correctly:
Use kinit to authenticate to Kerberos, for example.
kinit bredon@MYSQL.LOCAL

The command authenticates for the Kerberos principal named bredon@MYSQL.LOCAL. Enter the principal's password when the command prompts for it. The KDC returns a TGT that is cached on the client side for use by other Kerberos-aware applications.
Use klist to check whether the TGT was obtained correctly. 

The output should be similar to this:
Ticket cache: FILE:/tmp/krb5cc_244306
Default principal: bredon@MYSQL.LOCAL
Valid starting                 Expires                           Service principal
03/23/2020 08:18:33  03/23/2020 18:18:33  krbtgt/MYSQL.LOCAL@MYSQL.LOCAL

If the ticket expiration time exceeds the desired maximum expiration, and Kerberos is enabled, check the LDAP server for the maximum lifetime of the Kerberos service Tickets expiration policy.  

If the lifetime exceeds the desired expiration time, this is a finding."
  desc 'fix', %q(Modify system settings to implement the organization-defined limit on the lifetime of cached authenticators.

Configure the MySQL server for GSSAPI/Kerberos LDAP authentication plugin to use the GSSAPI/Kerberos authentication method.

Following is an example of plugin-related settings the server my.cnf file might contain:
[mysqld]
plugin-load-add=authentication_ldap_sasl.so
authentication_ldap_sasl_auth_method_name="GSSAPI"
authentication_ldap_sasl_server_host=198.51.100.10
authentication_ldap_sasl_server_port=389
authentication_ldap_sasl_bind_root_dn="cn=admin,cn=users,dc=MYSQL,dc=LOCAL"
authentication_ldap_sasl_bind_root_pwd="password"
authentication_ldap_sasl_bind_base_dn="cn=users,dc=MYSQL,dc=LOCAL"
authentication_ldap_sasl_user_search_attr="sAMAccountName"

Create account(s) using Kerberos Authentication.
For example:
CREATE USER 'bredon@MYSQL.LOCAL'
  IDENTIFIED WITH authentication_ldap_sasl
  BY '#krb_grp=proxied_krb_user';

CREATE USER 'proxied_krb_user'
  IDENTIFIED WITH mysql_no_login;
GRANT ALL
  ON krb_user_db.*
  TO 'proxied_krb_user';

GRANT PROXY
  ON 'proxied_krb_user'
  TO 'bredon@MYSQL.LOCAL’;)
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38396r623651_chk'
  tag severity: 'medium'
  tag gid: 'V-235177'
  tag rid: 'SV-235177r638812_rule'
  tag stig_id: 'MYS8-00-010300'
  tag gtitle: 'SRG-APP-000400-DB-000367'
  tag fix_id: 'F-38359r623652_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
