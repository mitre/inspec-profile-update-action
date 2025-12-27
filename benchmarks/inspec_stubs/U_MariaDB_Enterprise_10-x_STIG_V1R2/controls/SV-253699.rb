control 'SV-253699' do
  title 'MariaDB, when utilizing PKI-based authentication, must validate certificates by performing RFC 5280-compliant certification path validation.'
  desc "The DoD standard for authentication is DoD-approved PKI certificates.

A certificate's certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate. Certification path validation includes checks such as certificate issuer trust, time validity and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses.

Database Management Systems that do not validate certificates by performing RFC 5280-compliant certification path validation are in danger of accepting certificates that are invalid and/or counterfeit. This could allow unauthorized access to the database."
  desc 'check', 'As the database administrator, list all users and their SSL setup by running the following:

MariaDB> SELECT user, host, ssl_type FROM mysql.user;

Use the result of the next query to verify the MariaDB Server is using certificates:

MariaDB>  STATUS;

Verify the line beginning with "SSL:" returns expected SSL information. 

Using the following query, verify SSL is configured as expected: 

MariaDB>  SHOW GLOBAL VARIABLES LIKE  %ssl% ;

If not configured as expected, this is a finding.'
  desc 'fix', 'As the administrator locate the MariaDB configuration file to change. This varies depending on setup and how configuration files are managed but should be in /etc/my.cnf.d/. It is recommended to have a separate configuration file within this directory for SSL connection information. 

In the [server] section add the lines for SSL:

ssl-ca=/path/to/ssl/ca-cert.pem
ssl-cert=/path/to/ssl/server-cert.pem
ssl-key=/path/to/ssl/server-key.pem

To fully implement SSL for MariaDB, the client settings and user accounts need to be set up as well. More information can be found here:
https://mariadb.com/kb/en/securing-connections-for-client-and-server/'
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57151r841620_chk'
  tag severity: 'medium'
  tag gid: 'V-253699'
  tag rid: 'SV-253699r841622_rule'
  tag stig_id: 'MADB-10-004000'
  tag gtitle: 'SRG-APP-000175-DB-000067'
  tag fix_id: 'F-57102r841621_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
