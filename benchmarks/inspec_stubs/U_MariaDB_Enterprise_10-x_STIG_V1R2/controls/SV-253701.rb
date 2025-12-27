control 'SV-253701' do
  title 'MariaDB must map PKI ID to an associated user account.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates. Once a PKI is validated, it is mapped to the DBMS user account for the authentication identity and then can be used for authorization decisions.'
  desc 'check', 'Query all users to confirm issuer and subject are configured correctly: 

MariaDB>SELECT user, host, ssl_type, CAST(x509_issuer AS CHAR) AS issuer, CAST(x509_subject AS CHAR) AS subject FROM mysql.user;

If users are not mapped correctly, this is a finding.'
  desc 'fix', "Example command to create users with proper X509 certificate subject and issuer: 

MariaDB>CREATE USER 'janedoe'@'%' IDENTIFIED BY 'Some_Password_Here_$9'
REQUIRE SUBJECT '/C=US/ST=Ohio/L=Columbus/O=MariaDB Corporation/CN=Jane Doe'
AND ISSUER '/C=US/ST=Ohio/L=Columbus/O=MariaDB Corporation/CN=MariaDB CA';"
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57153r841626_chk'
  tag severity: 'medium'
  tag gid: 'V-253701'
  tag rid: 'SV-253701r841628_rule'
  tag stig_id: 'MADB-10-004200'
  tag gtitle: 'SRG-APP-000177-DB-000069'
  tag fix_id: 'F-57104r841627_fix'
  tag 'documentable'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
