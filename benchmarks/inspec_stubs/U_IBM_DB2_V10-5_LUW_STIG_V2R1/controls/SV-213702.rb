control 'SV-213702' do
  title 'DB2 must use NIST FIPS 140-2 validated cryptographic modules for cryptographic operations.'
  desc 'Use of weak or not validated cryptographic algorithms undermines the purposes of utilizing encryption and digital signatures to protect data.  Weak algorithms can be easily broken and not validated cryptographic modules may not implement algorithms correctly. Unapproved cryptographic modules or algorithms should not be relied on for authentication, confidentiality or integrity. Weak cryptography could allow an attacker to gain access to and modify data stored in the database as well as the administration settings of the DBMS.

Applications, including DBMSs, utilizing cryptography are required to use approved NIST FIPS 140-2 validated cryptographic modules that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.  

The security functions validated as part of FIPS 140-2 for cryptographic modules are described in FIPS 140-2 Annex A.

The cryptographic functionality in IBM DB2 for LUW includes features that are fully FIPS 140-2 validated, and others that are not.  To be sure of using only FIPS 140-2 validated modules, specify SSL (TLS) for communication and IBM Database Native Encryption for data at rest.

The decision whether to employ cryptography is the responsibility of the information owner/steward, who exercises discretion within the framework of applicable rules, policies, and law.'
  desc 'check', 'If it has been determined that encryption is not required, this is not a finding.

Review the cryptographic configuration.  

If SSL/TLS is not specified for encryption of communications, this is a finding. See below for more detailed instructions.

If IBM Database Native Encryption is not specified for encryption of data at rest, this is a finding. See below for more detailed instructions.

To Verify SSL is in use:
Check the DB2 registry variable DB2COMM to include SSL.

     $db2set -all

If DB2COMM does not include SSL, this is a finding. 

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

The above settings ensure that all connections over SSL in any CLP or Java application strictly adhere to NIST SP 800-131A.

To Verify DB2 native encryption is being used, run the following SQL Query:
DB2> SELECT SUBSTR(object_name,1,8) AS NAME, SUBSTR(object_type,1,8) TYPE, SUBSTR(algorithm,1,8) ALGORITHM 
           FROM TABLE(sysproc.admin_get_encryption_info())

If value of Algorithm is NULL for the database, this is a finding.

If the database is not encrypted with native encryption or any third-party tool, this is a finding.'
  desc 'fix', 'Modify the cryptographic configuration to employ SSL/TLS for encryption of communications.

Modify the cryptographic configuration to employ IBM Database Native Encryption for encryption of data at rest.'
  impact 0.7
  ref 'DPMS Target IBM DB2 V10.5 LUW'
  tag check_id: 'C-14923r917665_chk'
  tag severity: 'high'
  tag gid: 'V-213702'
  tag rid: 'SV-213702r917666_rule'
  tag stig_id: 'DB2X-00-004600'
  tag gtitle: 'SRG-APP-000179-DB-000114'
  tag fix_id: 'F-14921r295156_fix'
  tag 'documentable'
  tag legacy: ['SV-89167', 'V-74493']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
