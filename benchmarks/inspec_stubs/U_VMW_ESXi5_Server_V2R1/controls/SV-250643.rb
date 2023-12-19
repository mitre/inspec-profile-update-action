control 'SV-250643' do
  title 'The operating system must terminate the network connection associated with a communications session at the end of the session or after an organization-defined time period of inactivity.'
  desc 'If ESXi Shell is enabled on the host and a user neglects to initiate an SSH session the idle connection will remain available indefinitely increasing the potential for someone to gain privileged access to the host.'
  desc 'check', 'From the vSphere client select the host and click "Configuration >> Advanced Settings". Select "UserVars.ESXiShellTimeOut" parameter and verify it is set to a value not to exceed 900 seconds (15 minutes). A value of 0 disables the ESXi Shell timeout.

If the "UserVars.ESXiShellTimeOut" parameter is set to a value less than 1 or greater than 900, this is a finding.'
  desc 'fix', 'From the vSphere client select the host and click "Configuration >> Advanced Settings". Select UserVars.ESXiShellTimeOut parameter and configure it to a value not to exceed 900 seconds (15 minutes). A value of 0 disables the ESXi Shell timeout.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54078r798926_chk'
  tag severity: 'medium'
  tag gid: 'V-250643'
  tag rid: 'SV-250643r798928_rule'
  tag stig_id: 'SRG-OS-000163-ESXI5'
  tag gtitle: 'SRG-OS-000163-VMM-000700'
  tag fix_id: 'F-54032r798927_fix'
  tag 'documentable'
  tag legacy: ['V-39405', 'SV-51263']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
