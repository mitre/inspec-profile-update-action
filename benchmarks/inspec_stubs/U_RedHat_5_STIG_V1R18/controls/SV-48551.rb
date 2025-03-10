control 'SV-48551' do
  title 'Graphical desktop environments provided by the system must have automatic lock enabled.'
  desc 'If graphical desktop sessions do not lock the session after 15 minutes of inactivity, requiring re-authentication to resume operations, the system or individual data could be compromised by an alert intruder who could exploit the oversight. This requirement applies to graphical desktop environments provided by the system to locally attached displays and input devices as well as to graphical desktop environments provided to remote systems, including thin clients.'
  desc 'check', 'If the "xorg-x11-server-Xorg" package is not installed, this is not applicable.

For the Gnome screen saver, check the lock_enabled flag.

Procedure:
# gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/lock_enabled
If this does not return "true", this is a finding.'
  desc 'fix', 'For the Gnome screen saver, set the lock_enabled flag.

Procedure:
# gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --type bool --set /apps/gnome-screensaver/lock_enabled true'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-45195r1_chk'
  tag severity: 'medium'
  tag gid: 'V-27284'
  tag rid: 'SV-48551r1_rule'
  tag stig_id: 'GEN000500-3'
  tag gtitle: 'GEN000500-3'
  tag fix_id: 'F-33042r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
