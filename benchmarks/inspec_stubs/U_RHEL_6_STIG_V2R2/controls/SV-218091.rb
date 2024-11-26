control 'SV-218091' do
  title 'The system must allow locking of graphical desktop sessions.'
  desc 'The ability to lock graphical desktop sessions manually allows users to easily secure their accounts should they need to depart from their workstations temporarily.'
  desc 'check', 'If the GConf2 package is not installed, this is not applicable.

Verify the keybindings for the Gnome screensaver:

# gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome_settings_daemon/keybindings/screensaver

If no output is visible, this is a finding.'
  desc 'fix', 'Run the following command to set the Gnome desktop keybinding for locking the screen:

# gconftool-2
--direct \\
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \\
--type string \\
--set /apps/gnome_settings_daemon/keybindings/screensaver "<Control><Alt>l"

Another keyboard sequence may be substituted for "<Control><Alt>l", which is the default for the Gnome desktop.'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19572r377288_chk'
  tag severity: 'low'
  tag gid: 'V-218091'
  tag rid: 'SV-218091r603264_rule'
  tag stig_id: 'RHEL-06-000508'
  tag gtitle: 'SRG-OS-000030'
  tag fix_id: 'F-19570r377289_fix'
  tag 'documentable'
  tag legacy: ['SV-50274', 'V-38474']
  tag cci: ['CCI-000058']
  tag nist: ['AC-11 a']
end
