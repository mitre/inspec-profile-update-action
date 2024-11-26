control 'SV-214111' do
  title 'PostgreSQL, when utilizing PKI-based authentication, must validate certificates by performing RFC 5280-compliant certification path validation.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates.

A certificate’s certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate. Certification path validation includes checks such as certificate issuer trust, time validity and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses.

Database Management Systems that do not validate certificates by performing RFC 5280-compliant certification path validation are in danger of accepting certificates that are invalid and/or counterfeit. This could allow unauthorized access to the database.'
  desc 'check', 'Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA. 

To verify that a CRL file exists, as the database administrator (shown here as "postgres"), run the following: 

$ sudo su - postgres 
$ psql -c "SHOW ssl_crl_file" 

If this is not set to a CRL file, this is a finding. 

Next verify the existence of the CRL file by checking the directory set in postgresql.conf in the ssl_crl_file parameter from above: 

Note: If no directory is specified, then the CRL file should be located in the same directory as postgresql.conf (PGDATA). 

If the CRL file does not exist, this is a finding. 

Next, verify that hostssl entries in pg_hba.conf have "cert" and "clientcert=1" enabled: 

$ sudo su - postgres 
$ grep hostssl ${PGDATA?}/pg_hba.conf 

If hostssl entries do not contain cert or clientcert=1, this is a finding. 

If certificates are not being validated by performing RFC 5280-compliant certification path validation, this is a finding.'
  desc 'fix', %q(Note: The following instructions use the PGDATA and PGVER environment variables. See supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

To configure PostgreSQL to use SSL, see supplementary content APPENDIX-G. 

To generate a Certificate Revocation List, see the official Red Hat Documentation: https://access.redhat.com/documentation/en-US/Red_Hat_Update_Infrastructure/2.1/html/Administration_Guide/chap-Red_Hat_Update_Infrastructure-Administration_Guide-Certification_Revocation_List_CRL.html 

As the database administrator (shown here as "postgres"), copy the CRL file into the data directory: 

First, as the system administrator, copy the CRL file into the PostgreSQL Data Directory: 

$ sudo cp root.crl ${PGDATA?}/root.crl 

As the database administrator (shown here as "postgres"), set the ssl_crl_file parameter to the filename of the CRL: 

$ sudo su - postgres 
$ vi ${PGDATA?}/postgresql.conf 
ssl_crl_file = 'root.crl' 

Next, in pg_hba.conf, require ssl authentication: 

$ sudo su - postgres 
$ vi ${PGDATA?}/pg_hba.conf 
hostssl <database> <user> <address> cert clientcert=1 

Now, as the system administrator, reload the server with the new configuration: 

# SYSTEMD SERVER ONLY 
$ sudo systemctl reload postgresql-${PGVER?}

# INITD SERVER ONLY 
$ sudo service postgresql-${PGVER?} reload)
  impact 0.5
  ref 'DPMS Target PostgreSQL 9.x'
  tag check_id: 'C-15327r360964_chk'
  tag severity: 'medium'
  tag gid: 'V-214111'
  tag rid: 'SV-214111r508027_rule'
  tag stig_id: 'PGS9-00-007000'
  tag gtitle: 'SRG-APP-000175-DB-000067'
  tag fix_id: 'F-15325r360965_fix'
  tag 'documentable'
  tag legacy: ['SV-87631', 'V-72979']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
