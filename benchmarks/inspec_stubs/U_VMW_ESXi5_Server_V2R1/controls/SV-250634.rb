control 'SV-250634' do
  title 'The system must set a timeout for the ESXi Shell to automatically disable itself after a predetermined period.'
  desc 'The ESXiShellTimeout setting is the number of seconds that can elapse before a logon occurs after the ESXi Shell is enabled. After the timeout period, if a logon has not occurred, the shell is disabled. Leaving the shell enabled unnecessarily increases the potential for someone to gain privileged access to the host'
  desc 'check', 'From the vSphere client select the host and click "Configuration >> Advanced Settings". Select "UserVars.ESXiShellTimeOut" parameter and verify it is set to a value not to exceed 900 seconds (15 minutes). A value of 0 disables the ESXi Shell timeout. 

If the "UserVars.ESXiShellTimeOut" parameter is set to a value less than 1 or greater than 900, this is a finding.'
  desc 'fix', 'From the vSphere client select the host and click "Configuration >> Advanced Settings". Select UserVars.ESXiShellTimeOut parameter and configure it to a value not to exceed 900 seconds (15 minutes). A value of 0 disables the ESXi Shell timeout.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54069r798899_chk'
  tag severity: 'medium'
  tag gid: 'V-250634'
  tag rid: 'SV-250634r798901_rule'
  tag stig_id: 'SRG-OS-000126-ESXI5'
  tag gtitle: 'SRG-OS-000126-VMM-000640'
  tag fix_id: 'F-54023r798900_fix'
  tag 'documentable'
  tag legacy: ['SV-51250', 'V-39392']
  tag cci: ['CCI-000879']
  tag nist: ['MA-4 e']
end
