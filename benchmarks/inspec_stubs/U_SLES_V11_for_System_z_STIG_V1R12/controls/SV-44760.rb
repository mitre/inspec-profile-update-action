control 'SV-44760' do
  title 'The system must require authentication upon booting into single-user and maintenance modes.'
  desc 'If the system does not require valid root authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system.'
  desc 'check', "Check if the system requires a password for entering single-user mode.
# grep '~:S:' /etc/inittab
If /sbin/sulogin is not listed, this is a finding."
  desc 'fix', 'Edit /etc/inittab and set sulogin to run in single-user mode.
Example line in /etc/inittab:
# what to do in single-user mode
ls:S:wait:/etc/init.d/rc S
~~:S:respawn:/sbin/sulogin'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42265r1_chk'
  tag severity: 'medium'
  tag gid: 'V-756'
  tag rid: 'SV-44760r1_rule'
  tag stig_id: 'GEN000020'
  tag gtitle: 'GEN000020'
  tag fix_id: 'F-38210r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
