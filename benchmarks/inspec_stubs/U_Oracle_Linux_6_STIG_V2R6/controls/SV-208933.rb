control 'SV-208933' do
  title 'The graphical desktop environment must set the idle timeout to no more than 15 minutes.'
  desc 'Setting the idle delay controls when the screensaver will start, and can be combined with screen locking to prevent access from passersby.'
  desc 'check', 'If the GConf2 package is not installed, this is not applicable.

To check the current idle time-out value, run the following command:

$ gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/idle_delay

If properly configured, the output should be "15".

If it is not, this is a finding.'
  desc 'fix', 'Run the following command to set the idle time-out value for inactivity in the GNOME desktop to 15 minutes: 

# gconftool-2 \\
--direct \\
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \\
--type int \\
--set /apps/gnome-screensaver/idle_delay 15'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9186r357779_chk'
  tag severity: 'medium'
  tag gid: 'V-208933'
  tag rid: 'SV-208933r793719_rule'
  tag stig_id: 'OL6-00-000257'
  tag gtitle: 'SRG-OS-000029'
  tag fix_id: 'F-9186r357780_fix'
  tag 'documentable'
  tag legacy: ['V-50823', 'SV-65029']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
