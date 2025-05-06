control 'SV-224169' do
  title 'The EDB Postgres Advanced Server, when utilizing PKI-based authentication, must validate certificates by performing RFC 5280-compliant certification path validation.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates.

A certificate’s certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate. Certification path validation includes checks such as certificate issuer trust, time validity, and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses.

Database Management Systems that do not validate certificates by performing RFC 5280-compliant certification path validation are in danger of accepting certificates that are invalid and/or counterfeit. This could allow unauthorized access to the database.'
  desc 'check', 'Verify that hostssl entries in pg_hba.conf have "clientcert=1" enabled.

Note that the default location for the pg_hba.conf file is in the postgresql data directory. The location of the pg_hba.conf file for a running postgres instance can be found using the following command run from a Windows command prompt:

 psql -d <database name> -U <database superuser name> -c "SHOW hba_file"

where, <database name> is any database in the EDB postgres instance and <database superuser name> is a database superuser. By default, a database named "edb" and a superuser named "enterprisedb" are installed with EDB Postgres Advanced Server (EPAS).

Open the pg_hba.conf file in a text editor and inspect the contents of the file. If any uncommented lines have TYPE of "hostssl" but do not include "clientcert=1" in the OPTIONS column at the end of the line, this is a finding.

Optionally, the following command can be run from a Windows command prompt to identify any uncommented lines in the pg_hba.conf file that may be using these methods: 

 type <postgresql data directory>\\pg_hba.conf | findstr /N "hostssl" | find /V /N "#"

Note: For the command above, if the path to the pg_hba.conf file contains spaces in it, the path to the file (including the file name) should be placed in double quotes. 

If any uncommented lines are reported using the above command that show a TYPE of "hostssl" but do not include "clientcert=1" in the OPTIONS column at the end of the line, this is a finding.'
  desc 'fix', 'Open the "<postgresql data directory>\\pg_hba.conf" in an editor. 

Note that the default location for the pg_hba.conf file is in the postgresql data directory. The location of the pg_hba.conf file for a running postgres instance can be found using the following command run from a Windows command prompt:

 psql -d <database name> -U <database superuser name> -c "SHOW hba_file"

where, <database name> is any database in the EDB postgres instance and <database superuser name> is a database superuser. By default, a database named "edb" and a superuser named "enterprisedb" are installed with EDB Postgres Advanced Server (EPAS).

For any rows that have TYPE of "hostssl", append "clientcert=1" in the OPTIONS column at the end of the line.'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25842r495525_chk'
  tag severity: 'medium'
  tag gid: 'V-224169'
  tag rid: 'SV-224169r508023_rule'
  tag stig_id: 'EP11-00-004500'
  tag gtitle: 'SRG-APP-000175-DB-000067'
  tag fix_id: 'F-25830r495526_fix'
  tag 'documentable'
  tag legacy: ['SV-109469', 'V-100365']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
