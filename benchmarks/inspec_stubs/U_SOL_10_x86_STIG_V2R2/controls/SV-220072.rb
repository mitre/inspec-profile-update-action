control 'SV-220072' do
  title 'The system must require authentication upon booting into single-user and maintenance modes.'
  desc 'If the system does not require valid root authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system.'
  desc 'check', 'This can be checked in the /etc/default/sulogin file (on Solaris 5.X systems) to check if the system runs sulogin, or an equivalent, when booting into single-user mode.'
  desc 'fix', 'Edit /etc/default/sulogin and set PASSREQ=YES or remove /etc/default/sulogin entirely.  

NOTE: This is a default on Solaris 5.5.1 and later.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-21781r488201_chk'
  tag severity: 'medium'
  tag gid: 'V-220072'
  tag rid: 'SV-220072r603266_rule'
  tag stig_id: 'GEN000020'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-21780r488202_fix'
  tag 'documentable'
  tag legacy: ['V-756', 'SV-36752']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
