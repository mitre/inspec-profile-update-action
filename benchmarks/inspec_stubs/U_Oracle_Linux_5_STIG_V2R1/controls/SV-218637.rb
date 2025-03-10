control 'SV-218637' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20112r562888_chk'
  tag severity: 'medium'
  tag gid: 'V-218637'
  tag rid: 'SV-218637r603259_rule'
  tag stig_id: 'GEN006060'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-20110r562889_fix'
  tag 'documentable'
  tag legacy: ['V-4321', 'SV-64125']
  tag cci: ['CCI-001436', 'CCI-000381']
  tag nist: ['AC-17 (8)', 'CM-7 a']
end
