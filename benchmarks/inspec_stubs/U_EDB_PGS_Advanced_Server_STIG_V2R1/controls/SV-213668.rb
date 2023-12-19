control 'SV-213668' do
  title 'The EDB Postgres Advanced Server must be configured on a platform that has a NIST certified FIPS 140-2 installation of OpenSSL.'
  desc 'Postgres uses OpenSSL for the underlying encryption layer. Currently only Red Hat Enterprise Linux is certified as a FIPS 140-2 distribution of OpenSSL. For other operating systems, users must obtain or build their own FIPS 140-2 OpenSSL libraries.'
  desc 'check', 'If the Postgres Plus Advanced Server is not installed on Red Hat Enterprise Linux (RHEL), this is a finding.'
  desc 'fix', 'Install Postgres Plus Advanced Server on RHEL or ensure that FIPS 140-2 certified OpenSSL libraries are used by the DBMS.'
  impact 0.7
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14890r290316_chk'
  tag severity: 'high'
  tag gid: 'V-213668'
  tag rid: 'SV-213668r508024_rule'
  tag stig_id: 'PPS9-00-013200'
  tag gtitle: 'SRG-APP-000179-DB-000114'
  tag fix_id: 'F-14888r290317_fix'
  tag 'documentable'
  tag legacy: ['V-69085', 'SV-83689']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
