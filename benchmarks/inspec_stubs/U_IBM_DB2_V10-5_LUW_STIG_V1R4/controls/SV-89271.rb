control 'SV-89271' do
  title 'DB2 must use NSA-approved cryptography to protect classified information in accordance with the data owners requirements.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

It is the responsibility of the data owner to assess the cryptography requirements in light of applicable federal laws, Executive Orders, directives, policies, regulations, and standards.

NSA-approved cryptography for classified networks is hardware based. This requirement addresses the compatibility of a DBMS with the encryption devices.'
  desc 'check', 'If the database is in the unclassified environment, this is not applicable (NA).

Verify the instance configuration parameters so that the instance is strictly compliant with NIST SP 800-131A. 

Check the DB2 registry variable DB2COMM is set to SSL:

$db2set all

If DB2COMM is not set to SSL, this is a finding. 

Find the value of SSL_VERSIONS by running: 

$db2 get dbm cfg

If SSL_VERSIONS is not set to TLSV12, this is a finding.

Find the value of SSL_CIPHERSPECS by running:

$db2 get dbm cfg

If SSL_CIPHERSPECS is not set to a symmetric algorithm key length that is greater than or equal to 112, this is a finding. 

Find the value of SSL_SVC_LABEL by running:

$db2 get dbm cfg

If the parameter SSL_SVC_LABEL is not set to a certificate with RSA key length that is greater than or equal to 2048, this is a finding. 

If the certificate does not have a digital signature with minimum SHA2, this is a finding.

The above settings ensure that all connections over SSL in any CLP or Java application strictly adhere to NIST SP 800-131A.'
  desc 'fix', 'Setting instance configuration parameters so that the instance is strictly compliant with NIST SP 800-131A. 

Set the DB2 registry variable DB2COMM to SSL:

$db2set DB2COMM=SSL 

Set the DB2 database manager configuration parameter SSL_VERSIONS to TLSV12:

$db2 update dbm cfg using SSL_VERSIONS TLSV12 

Set the DB2 database manager configuration parameter SSL_CIPHERSPECS to a symmetric algorithm key length that is greater than or equal to 112:

$db2 update dbm cfg using SSL_CIPHERSPECS TLS_RSA_WITH_AES_256_GCM_SHA384 

Set the database manager configuration parameter SSL_SVC_LABEL to a certificate with RSA key length that is greater than or equal to 2048. That certificate must also have a digital signature with minimum SHA2. 

Create the certificate. Example:

$gsk8capicmd_64 -cert -create -db "mydbserver.kdb" -pw "password" -size 2048 -sigalg SHA256WithRSA -label "myselfsigned_SHA2_2K" -dn "CN=myhost.mycompany.com,O=myOrganization, OU=myOrganizationUnit,L=myLocation,ST=ON,C=CA"

$db2 update dbm cfg using SSL_SVR_LABEL myselfsigned_SHA_2K

Note: Here is an example of SSL set up on Linux:

1. Create a directory "ssl"
$mkdir ssl
2. Make sure gsk8capicmd_64 command in PATH $ export PATH=$PATH:/home/db2inst1/sqllib/gskit/bin
3. Make sure library is in path $ echo $LD_LIBRARY_PATH /home/db2inst1/sqllib/lib64:/home/db2inst1/sqllib/lib64/gskit:/home/db2inst1/sqllib/lib32
4. Go to ssl directory (/home/db2inst1/ssl)
5. Create Server key database
$db2inst1@potserver:~/ssl> gsk8capicmd_64 -keydb -create -db "mydbserver.kdb" -pw "password" -stash
$db2inst1@potserver:~/ssl> ls
$mydbserver.crl mydbserver.kdb mydbserver.rdb mydbserver.sth
6. To create a self-signed certificate with a label of myselfsigned, use the GSKCapiCmd command as shown in the following example:
$gsk8capicmd_64 -cert -create -db "mydbserver.kdb" -pw "password" -label "myselfsigned" -dn "CN=myhost.mycompany.com,O=myOrganization, OU=myOrganizationUnit,L=myLocation,ST=ON,C=CA"
7. Extract the certificate you just created to a file, so that you can distribute it to computers running clients that will be establishing SSL connections to your DB2 server. For example, the following GSKCapiCmd command extracts the certificate to a file called mydbserver.arm:
$gsk8capicmd_64 -cert -extract -db "mydbserver.kdb" -pw "password" -label "myselfsigned" -target "mydbserver.arm" -format ascii -fips
8. Set database manager configuration parameters:
$db2 update dbm cfg using SSL_SVR_KEYDB /home/db2inst1/ssl/mydbserver.kdb
$db2 update dbm cfg using SSL_SVR_STASH /home/db2inst1/ssl/mydbserver.sth
$db2 update dbm cfg using SSL_SVR_LABEL SSLLabel
$db2 update dbm cfg using SSL_SVCENAME 50602 
9. Add the value SSL to the DB2COMM registry variable. For example:
$db2set -i db2inst1 DB2COMM=SSL
or 
$db2set -i db2inst1 DB2COMM=SSL'
  impact 0.7
  ref 'DPMS Target IBM DB2 LUW 10.5 for Linux'
  tag check_id: 'C-74483r2_chk'
  tag severity: 'high'
  tag gid: 'V-74597'
  tag rid: 'SV-89271r2_rule'
  tag stig_id: 'DB2X-00-008600'
  tag gtitle: 'SRG-APP-000416-DB-000380'
  tag fix_id: 'F-81197r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
