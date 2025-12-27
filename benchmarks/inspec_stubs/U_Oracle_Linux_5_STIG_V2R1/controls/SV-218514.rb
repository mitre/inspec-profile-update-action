control 'SV-218514' do
  title 'The rlogind service must not be running.'
  desc 'The rlogind process provides a typically unencrypted, host-authenticated remote access service.  SSH should be used in place of this service.'
  desc 'check', 'Check the rlogind configuration.
# cat /etc/xinetd.d/rlogin
If the file exists and does not contain "disable = yes" this is a finding.'
  desc 'fix', 'Remove or disable the rlogin configuration and restart xinetd.
# rm /etc/xinetd.d/rlogin ; service xinetd restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19989r555740_chk'
  tag severity: 'medium'
  tag gid: 'V-218514'
  tag rid: 'SV-218514r603259_rule'
  tag stig_id: 'GEN003830'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-19987r555741_fix'
  tag 'documentable'
  tag legacy: ['V-22432', 'SV-64019']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
