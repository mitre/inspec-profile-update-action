control 'SV-233623' do
  title 'The DBMS must be configured on a platform that has a NIST certified FIPS 140-2 installation of OpenSSL.'
  desc 'Postgres uses OpenSSL for the underlying encryption layer. Currently only Red Hat Enterprise Linux is certified as a FIPS 140-2 distribution of OpenSSL. For other operating systems, users must obtain or build their own FIPS 140-2 OpenSSL libraries.'
  desc 'check', 'If the deployment incorporates a custom build of the operating system and PostgreSQL guaranteeing the use of FIPS 140-2- compliant OpenSSL, this is not a finding. 

If PostgreSQL is not installed on an OS found in the CMVP (https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules), this is a finding. 

If FIPS encryption is not enabled, this is a finding.'
  desc 'fix', 'Install PostgreSQL with FIPS-compliant cryptography enabled on an OS found in the CMVP (https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules) or by other means, ensure that FIPS 140-2-certified OpenSSL libraries are used by the DBMS.'
  impact 0.7
  ref 'DPMS Target Crunchy Data PostgreSQL'
  tag check_id: 'C-36817r607092_chk'
  tag severity: 'high'
  tag gid: 'V-233623'
  tag rid: 'SV-233623r617333_rule'
  tag stig_id: 'CD12-00-012800'
  tag gtitle: 'SRG-APP-000179-DB-000114'
  tag fix_id: 'F-36782r607093_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
