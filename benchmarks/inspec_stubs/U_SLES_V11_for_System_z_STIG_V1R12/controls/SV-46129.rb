control 'SV-46129' do
  title 'The system must not run Samba unless needed.'
  desc 'Samba is a tool used for the sharing of files and printers between Windows and UNIX operating systems.  It provides access to sensitive files and, therefore, poses a security risk if compromised.'
  desc 'check', 'Check the system for a running Samba server.

Procedure:
# ps -ef |grep smbd

If the Samba server is running, ask the SA if the Samba server is operationally required. If it is not, this is a finding.'
  desc 'fix', 'If there is no functional need for Samba and the daemon is running, disable the daemon by killing the process ID as noted from the output of ps -ef |grep smbd. The samba package should also be removed or not installed if there is no functional requirement.

Procedure:
rpm -qa |grep samba

This will show if "samba" is installed. Packages that start with “yast2-samba” are NOT part of the Samba software suite.  To remove:

rpm -e samba
SuSEconfig'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43388r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4321'
  tag rid: 'SV-46129r1_rule'
  tag stig_id: 'GEN006060'
  tag gtitle: 'GEN006060'
  tag fix_id: 'F-39471r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
