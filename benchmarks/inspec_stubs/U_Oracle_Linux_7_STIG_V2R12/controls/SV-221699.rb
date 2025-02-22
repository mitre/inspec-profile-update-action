control 'SV-221699' do
  title 'The Oracle Linux operating system must require authentication upon booting into single-user and maintenance modes.'
  desc 'If the system does not require valid root authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system.'
  desc 'check', 'Verify the operating system must require authentication upon booting into single-user and maintenance modes.

Check that the operating system requires authentication upon booting into single-user mode with the following command:

# grep -i execstart /usr/lib/systemd/system/rescue.service | grep -i sulogin

ExecStart=-/bin/sh -c "/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"

If "ExecStart" does not have "/usr/sbin/sulogin" as an option, this is a finding.'
  desc 'fix', 'Configure the operating system to require authentication upon booting into single-user and maintenance modes.

Add or modify the "ExecStart" line in "/usr/lib/systemd/system/rescue.service" to include "/usr/sbin/sulogin":

ExecStart=-/bin/sh -c "/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23414r419169_chk'
  tag severity: 'medium'
  tag gid: 'V-221699'
  tag rid: 'SV-221699r603260_rule'
  tag stig_id: 'OL07-00-010481'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-23403r419170_fix'
  tag 'documentable'
  tag legacy: ['V-99137', 'SV-108241']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
