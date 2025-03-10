control 'SV-218036' do
  title 'The x86 Ctrl-Alt-Delete key sequence must be disabled.'
  desc 'A locally logged-in user who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot. In the GNOME graphical environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken.'
  desc 'check', 'To ensure the system is configured to log a message instead of rebooting the system when Ctrl-Alt-Delete is pressed, ensure the following line is in "/etc/init/control-alt-delete.override":

exec /usr/bin/logger -p authpriv.notice "Ctrl-Alt-Delete pressed"

If the system is not configured to block the shutdown command when Ctrl-Alt-Delete is pressed, this is a finding.'
  desc 'fix', 'By default, the system includes the following line in "/etc/init/control-alt-delete.conf" to reboot the system when the Ctrl-Alt-Delete key sequence is pressed:

exec /sbin/shutdown -r now "Ctrl-Alt-Delete pressed"


To configure the system to log a message instead of rebooting the system, add the following line to "/etc/init/control-alt-delete.override" to read as follows:

exec /usr/bin/logger -p authpriv.notice "Ctrl-Alt-Delete pressed"'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19517r377123_chk'
  tag severity: 'high'
  tag gid: 'V-218036'
  tag rid: 'SV-218036r603264_rule'
  tag stig_id: 'RHEL-06-000286'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-19515r377124_fix'
  tag 'documentable'
  tag legacy: ['V-38668', 'SV-50469']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
