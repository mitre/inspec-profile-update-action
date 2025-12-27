control 'SV-218221' do
  title 'The graphical desktop environment must set the idle timeout to no more than 15 minutes.'
  desc 'If graphical desktop sessions do not lock the session after 15 minutes of inactivity, requiring re-authentication to resume operations, the system or individual data could be compromised by an alert intruder who could exploit the oversight. This requirement applies to graphical desktop environments provided by the system to locally attached displays and input devices as well as to graphical desktop environments provided to remote systems, including thin clients.'
  desc 'check', 'If the "xorg-x11-server-Xorg" package is not installed, this is not applicable.

For the Gnome screen saver, check the idle_delay setting.

Procedure:
# gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/idle_delay

If this does not return 15 or less, this is a finding.'
  desc 'fix', 'For the Gnome screen saver, set idle_delay to 15.

Procedure:
# gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --type int --set /apps/gnome-screensaver/idle_delay 15'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19696r568567_chk'
  tag severity: 'medium'
  tag gid: 'V-218221'
  tag rid: 'SV-218221r603259_rule'
  tag stig_id: 'GEN000500-2'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag fix_id: 'F-19694r568568_fix'
  tag 'documentable'
  tag legacy: ['V-27283', 'SV-63609']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
