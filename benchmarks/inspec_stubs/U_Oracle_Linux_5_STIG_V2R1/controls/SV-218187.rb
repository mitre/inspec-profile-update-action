control 'SV-218187' do
  title 'The system must require authentication upon booting into single-user and maintenance modes.'
  desc 'If the system does not require valid root authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system.'
  desc 'check', "Check if the system requires a password for entering single-user mode.
# grep ':S:' /etc/inittab
If /sbin/sulogin is not listed, this is a finding."
  desc 'fix', 'Edit /etc/inittab and set sulogin to run in single-user mode.
Example line in /etc/inittab:
~:S:wait:/sbin/sulogin

Note: The first field in the /etc/inittab line may be any sequence of 1-4 characters.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19662r553898_chk'
  tag severity: 'medium'
  tag gid: 'V-218187'
  tag rid: 'SV-218187r603259_rule'
  tag stig_id: 'GEN000020'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-19660r553899_fix'
  tag 'documentable'
  tag legacy: ['V-756', 'SV-63087']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
