control 'SV-208936' do
  title 'The system must display a publicly-viewable pattern during a graphical desktop environment session lock.'
  desc 'Setting the screensaver mode to blank-only conceals the contents of the display from passersby.'
  desc 'check', 'If the GConf2 package is not installed, this is not applicable.

To ensure the screensaver is configured to be blank, run the following command:

$ gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/mode

If properly configured, the output should be "blank-only".
If it is not, this is a finding.'
  desc 'fix', 'Run the following command to set the screensaver mode in the GNOME desktop to a blank screen: 

# gconftool-2 \\
--direct \\
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \\
--type string \\
--set /apps/gnome-screensaver/mode blank-only'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9189r357788_chk'
  tag severity: 'low'
  tag gid: 'V-208936'
  tag rid: 'SV-208936r793722_rule'
  tag stig_id: 'OL6-00-000260'
  tag gtitle: 'SRG-OS-000031'
  tag fix_id: 'F-9189r357789_fix'
  tag 'documentable'
  tag legacy: ['V-50829', 'SV-65035']
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end
