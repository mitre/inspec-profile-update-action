control 'SV-213668' do
  title 'The EDB Postgres Advanced Server must be configured on a platform that has a NIST certified FIPS 140-2 ior 140-3 nstallation of OpenSSL.'
  desc 'PostgreSQL uses OpenSSL for the underlying encryption layer. It must be installed on an operating system that contains a certified FIPS 140-2 or 140-3 distribution of OpenSSL. For other operating systems, users must obtain or build their own FIPS 140 OpenSSL libraries.'
  desc 'check', 'If the deployment incorporates a custom build of the operating system and PostgreSQL guaranteeing the use of FIPS 140-2 or 140-3 compliant OpenSSL, this is not a finding. 

If PostgreSQL is not installed on an OS found in the CMVP (https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules), this is a finding. 

If FIPS encryption is not enabled, this is a finding.'
  desc 'fix', 'Install PostgreSQL with FIPS-compliant cryptography enabled on an OS found in the CMVP (https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules) or by other means, ensure that FIPS 140-2 or 140-3 certified OpenSSL libraries are used by the DBMS.'
  impact 0.7
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14890r836852_chk'
  tag severity: 'high'
  tag gid: 'V-213668'
  tag rid: 'SV-213668r836854_rule'
  tag stig_id: 'PPS9-00-013200'
  tag gtitle: 'SRG-APP-000179-DB-000114'
  tag fix_id: 'F-14888r836853_fix'
  tag 'documentable'
  tag legacy: ['SV-83689', 'V-69085']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
