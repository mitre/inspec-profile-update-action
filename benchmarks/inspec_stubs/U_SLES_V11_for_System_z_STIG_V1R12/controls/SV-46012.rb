control 'SV-46012' do
  title 'The SSH daemon must be configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms.'
  desc 'DoD information systems are required to use FIPS 140-2 approved cryptographic hash functions.'
  desc 'check', %q(Check the SSH daemon configuration for allowed MACs.

Procedure:
# grep -i macs /etc/ssh/sshd_config | grep -v '^#' 

If no lines are returned, or the returned MACs list contains any MAC less than "hmac-sha1", this is a finding.)
  desc 'fix', 'Edit the SSH daemon configuration and remove any MACs less than "hmac-sha1". If necessary, add a "MACs" line.

Restart the SSH daemon.
# /sbin/service sshd restart'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43292r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22460'
  tag rid: 'SV-46012r3_rule'
  tag stig_id: 'GEN005507'
  tag gtitle: 'GEN005507'
  tag fix_id: 'F-39376r4_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
