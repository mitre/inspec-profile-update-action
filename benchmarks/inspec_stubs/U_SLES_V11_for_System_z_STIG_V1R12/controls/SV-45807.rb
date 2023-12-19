control 'SV-45807' do
  title 'The rexec daemon must not be running.'
  desc 'The rexecd process provides a typically unencrypted, host-authenticated remote access service.  SSH should be used in place of this service.'
  desc 'check', '# grep disable /etc/xinetd.d/rexec
If the service file exists and is not disabled, this is a finding.'
  desc 'fix', 'Edit /etc/xinetd.d/rexec and set "disable=yes"'
  impact 0.7
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43128r1_chk'
  tag severity: 'high'
  tag gid: 'V-4688'
  tag rid: 'SV-45807r1_rule'
  tag stig_id: 'GEN003840'
  tag gtitle: 'GEN003840'
  tag fix_id: 'F-39197r1_fix'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001435']
  tag nist: ['AC-17 (8)']
end
