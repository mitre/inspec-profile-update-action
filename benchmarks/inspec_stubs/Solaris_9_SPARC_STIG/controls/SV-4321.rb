control 'SV-4321' do
  title 'The system must not run Samba unless needed.'
  desc 'Samba is a tool used for the sharing of files and printers between Windows and UNIX operating systems.  It provides access to sensitive files and, therefore, poses a security risk if compromised.'
  desc 'fix', 'If there is no functional need for Samba and the daemon is running, disable the daemon by killing the process ID as noted from the output of ps -ef |grep smbd.  The utility should also be removed or not installed if there is no functional requirement.'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-4321'
  tag rid: 'SV-4321r2_rule'
  tag stig_id: 'GEN006060'
  tag gtitle: 'GEN006060'
  tag fix_id: 'F-4232r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCPD-1, ECSC-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
