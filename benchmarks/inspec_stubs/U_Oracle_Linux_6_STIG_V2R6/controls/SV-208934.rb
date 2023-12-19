control 'SV-208934' do
  title 'The graphical desktop environment must automatically lock after 15 minutes of inactivity and the system must require user reauthentication to unlock the environment.'
  desc 'Enabling idle activation of the screen saver ensures the screensaver will be activated after the idle delay. Applications requiring continuous, real-time screen display (such as network management products) require the login session does not have administrator rights and the display station is located in a controlled-access area.'
  desc 'check', 'If the GConf2 package is not installed, this is not applicable.

To check the screensaver mandatory use status, run the following command:

$ gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/idle_activation_enabled

If properly configured, the output should be "true".

If it is not, this is a finding.'
  desc 'fix', 'Run the following command to activate the screensaver in the GNOME desktop after a period of inactivity: 

# gconftool-2 --direct \\
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \\
--type bool \\
--set /apps/gnome-screensaver/idle_activation_enabled true'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9187r357782_chk'
  tag severity: 'medium'
  tag gid: 'V-208934'
  tag rid: 'SV-208934r793720_rule'
  tag stig_id: 'OL6-00-000258'
  tag gtitle: 'SRG-OS-000029'
  tag fix_id: 'F-9187r357783_fix'
  tag 'documentable'
  tag legacy: ['V-50825', 'SV-65031']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
