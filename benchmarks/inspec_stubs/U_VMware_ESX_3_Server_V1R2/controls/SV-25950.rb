control 'SV-25950' do
  title 'The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes.'
  desc 'Systems must employ cryptographic hashes for passwords using the SHA-2 family of algorithms or FIPS 140-2 approved successors. The use of unapproved algorithms may result in weak password hashes more vulnerable to compromise.'
  desc 'check', 'Determine if the system creates password hashes using a FIPS 140-2 approved cryptographic hashing algorithm. Consult OS documentation to determine the necessary configuration settings. If the system is not configured to generate password hashes using a FIPS 140-2 approved algorithm, this is a finding.'
  desc 'fix', 'Configure the system to use a FIPS 140-2 approved cryptographic hash algorithm for creating password hashes.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29094r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22303'
  tag rid: 'SV-25950r1_rule'
  tag stig_id: 'GEN000590'
  tag gtitle: 'GEN000590'
  tag fix_id: 'F-26093r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCNR-1, IAIA-1, IAIA-2'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
