control 'SV-204437' do
  title 'The Red Hat Enterprise Linux operating system must require authentication upon booting into single-user and maintenance modes.'
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
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4561r88503_chk'
  tag severity: 'medium'
  tag gid: 'V-204437'
  tag rid: 'SV-204437r603261_rule'
  tag stig_id: 'RHEL-07-010481'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-4561r88504_fix'
  tag 'documentable'
  tag legacy: ['V-77823', 'SV-92519']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
