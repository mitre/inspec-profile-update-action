control 'SV-35208' do
  title 'The system must not run Samba unless needed.'
  desc 'Samba is a tool used for the sharing of files and printers between Windows and UNIX operating systems.  It provides access to sensitive files and, therefore, poses a security risk if compromised.'
  desc 'check', 'Check the system for a running Samba server.
# ps -ef |grep -v grep | grep smbd

If the Samba server is running, ask the SA if the Samba server is operationally required. If it is not, this is a finding.'
  desc 'fix', 'If there is no functional need for Samba and the daemon is running, disable the daemon 
by killing the process ID as noted from the output of ps -ef |grep smbd. The utility should also be 
removed or not installed if there is no functional requirement.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36692r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4321'
  tag rid: 'SV-35208r1_rule'
  tag stig_id: 'GEN006060'
  tag gtitle: 'GEN006060'
  tag fix_id: 'F-32067r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
