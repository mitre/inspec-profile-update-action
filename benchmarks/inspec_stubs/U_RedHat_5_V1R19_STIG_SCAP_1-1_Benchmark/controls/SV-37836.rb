control 'SV-37836' do
  title 'The SSH client must be configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms.'
  desc 'DoD information systems are required to use FIPS 140-2 approved cryptographic hash functions.'
  desc 'fix', 'Edit the SSH client configuration and remove any MACs that are not hmac-sha1 or a better hmac algorithm that is on the FIPS 140-2 approved list. If necessary, add a MACs line.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22463'
  tag rid: 'SV-37836r2_rule'
  tag stig_id: 'GEN005512'
  tag gtitle: 'GEN005512'
  tag fix_id: 'F-32301r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
