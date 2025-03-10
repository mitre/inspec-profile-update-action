control 'SV-38718' do
  title 'The inetd time service must not be active on the system on the inetd daemon.'
  desc 'The time service is an internal inetd function is used by the rdate command.  This service is sometimes used to synchronize clocks at boot time.   The service is outdated.   Use the ntpdate command instead.'
  desc 'fix', 'Edit the /etc/inetd.conf file and comment out the time service line. 

Restart the inetd service.   
# refresh -s inetd'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-29514'
  tag rid: 'SV-38718r1_rule'
  tag stig_id: 'GEN009300'
  tag gtitle: 'GEN009300'
  tag fix_id: 'F-33072r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
