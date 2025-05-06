control 'SV-37867' do
  title 'The system must not run Samba unless needed.'
  desc 'Samba is a tool used for the sharing of files and printers between Windows and UNIX operating systems.  It provides access to sensitive files and, therefore, poses a security risk if compromised.'
  desc 'check', 'Check the system for a running Samba server.

Procedure:
# ps -ef |grep smbd

If the Samba server is running, ask the SA if the Samba server is operationally required. If it is not, this is a finding.'
  desc 'fix', 'If there is no functional need for Samba and the daemon is running, disable the daemon by killing the process ID as noted from the output of ps -ef |grep smbd. The samba package should also be removed or not installed if there is no functional requirement.

Procedure:
rpm -qa |grep samba

This will show whether "samba" or "samba3x" is installed. To remove:

rpm --erase samba
or
rpm --erase samba3x'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37082r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4321'
  tag rid: 'SV-37867r1_rule'
  tag stig_id: 'GEN006060'
  tag gtitle: 'GEN006060'
  tag fix_id: 'F-32354r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
