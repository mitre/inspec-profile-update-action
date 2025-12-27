control 'SV-220019' do
  title 'The system must require authentication upon booting into single-user and maintenance modes.'
  desc 'If the system does not require valid root authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system.'
  desc 'check', 'This can be checked in the /etc/default/sulogin file (on Solaris 5.X systems) to check if the system runs sulogin, or an equivalent, when booting into single-user mode.'
  desc 'fix', 'Edit /etc/default/sulogin and set PASSREQ=YES or remove /etc/default/sulogin entirely.  NOTE: This is a default on Solaris 5.5.1 and later.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-21728r482651_chk'
  tag severity: 'medium'
  tag gid: 'V-220019'
  tag rid: 'SV-220019r603265_rule'
  tag stig_id: 'GEN000020'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-21727r482652_fix'
  tag 'documentable'
  tag legacy: ['SV-36753', 'V-756']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
