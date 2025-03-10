control 'SV-46020' do
  title 'The SSH client must be configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms.'
  desc 'DoD information systems are required to use FIPS 140-2 approved cryptographic hash functions.'
  desc 'check', %q(Check the SSH client configuration for allowed MACs.
# grep -i macs /etc/ssh/ssh_config | grep -v '^#' 
If no lines are returned, or the returned MACs list contains any MAC less than "hmac-sha1", this is a finding.)
  desc 'fix', 'Edit the SSH client configuration and remove any MACs less than "hmac-sha1". If necessary, add a "MACs" line.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43296r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22463'
  tag rid: 'SV-46020r2_rule'
  tag stig_id: 'GEN005512'
  tag gtitle: 'GEN005512'
  tag fix_id: 'F-39384r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
