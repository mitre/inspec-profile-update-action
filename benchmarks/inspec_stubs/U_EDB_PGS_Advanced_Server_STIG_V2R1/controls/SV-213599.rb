control 'SV-213599' do
  title 'The EDB Postgres Advanced Server, when utilizing PKI-based authentication, must validate certificates by performing RFC 5280-compliant certification path validation.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates.

A certificate’s certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate. Certification path validation includes checks such as certificate issuer trust, time validity and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses.

Database Management Systems that do not validate certificates by performing RFC 5280-compliant certification path validation are in danger of accepting certificates that are invalid and/or counterfeit. This could allow unauthorized access to the database.'
  desc 'check', 'Open "<postgresql data directory>/pg_hba.conf" in a viewer or editor.  (The default path for the postgresql data directory is /var/lib/ppas/9.5/data, but this will vary according to local circumstances.)

If any rows have TYPE of "hostssl" but do not include "clientcert=1" in the OPTIONS column at the end of the line, this is a finding.'
  desc 'fix', 'Open "<postgresql data directory>/pg_hba.conf" in an editor.  (The default path for the postgresql data directory is /var/lib/ppas/9.5/data, but this will vary according to local circumstances.)

For any rows that have TYPE of "hostssl", append "clientcert=1" in the OPTIONS column at the end of the line.'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14821r290109_chk'
  tag severity: 'medium'
  tag gid: 'V-213599'
  tag rid: 'SV-213599r508024_rule'
  tag stig_id: 'PPS9-00-004500'
  tag gtitle: 'SRG-APP-000175-DB-000067'
  tag fix_id: 'F-14819r290110_fix'
  tag 'documentable'
  tag legacy: ['SV-83555', 'V-68951']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
