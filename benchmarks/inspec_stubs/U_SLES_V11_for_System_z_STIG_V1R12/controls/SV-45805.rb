control 'SV-45805' do
  title 'The rlogind service must not be running.'
  desc 'The rlogind process provides a typically unencrypted, host-authenticated remote access service.  SSH should be used in place of this service.'
  desc 'check', 'Check the rlogind configuration.
# cat /etc/xinetd.d/rlogin
If the file exists and does not contain "disable = yes" this is a finding.'
  desc 'fix', 'Remove or disable the rlogin configuration and restart xinetd.
# rm /etc/xinetd.d/rlogin ; service xinetd restart'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43126r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22432'
  tag rid: 'SV-45805r1_rule'
  tag stig_id: 'GEN003830'
  tag gtitle: 'GEN003830'
  tag fix_id: 'F-39195r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
