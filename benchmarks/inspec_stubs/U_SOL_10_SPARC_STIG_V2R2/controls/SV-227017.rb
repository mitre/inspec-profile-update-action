control 'SV-227017' do
  title 'The system must not run Samba unless needed.'
  desc 'Samba is a tool used for the sharing of files and printers between Windows and UNIX operating systems.  It provides access to sensitive files and, therefore, poses a security risk if compromised.'
  desc 'check', 'Check the system for a running Samba server.

Procedure:
# ps -ef |grep smbd

If the Samba server is running, ask the SA if the Samba server is operationally required.  If it is not, this is a finding.'
  desc 'fix', 'If there is no functional need for Samba and the daemon is running, disable the daemon by killing the process ID as noted from the output of ps -ef |grep smbd.  The utility should also be removed or not installed if there is no functional requirement.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29179r485402_chk'
  tag severity: 'medium'
  tag gid: 'V-227017'
  tag rid: 'SV-227017r603265_rule'
  tag stig_id: 'GEN006060'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-29167r485403_fix'
  tag 'documentable'
  tag legacy: ['V-4321', 'SV-4321']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
