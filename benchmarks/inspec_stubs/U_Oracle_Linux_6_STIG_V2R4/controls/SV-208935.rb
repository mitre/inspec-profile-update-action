control 'SV-208935' do
  title 'The graphical desktop environment must have automatic lock enabled.'
  desc 'Enabling the activation of the screen lock after an idle period ensures password entry will be required in order to access the system, preventing access by passersby.'
  desc 'check', 'If the GConf2 package is not installed, this is not applicable.

To check the status of the idle screen lock activation, run the following command:

$ gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/lock_enabled

If properly configured, the output should be "true".
If it is not, this is a finding.'
  desc 'fix', 'Run the following command to activate locking of the screensaver in the GNOME desktop when it is activated: 

# gconftool-2 --direct \\
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \\
--type bool \\
--set /apps/gnome-screensaver/lock_enabled true'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9188r357785_chk'
  tag severity: 'medium'
  tag gid: 'V-208935'
  tag rid: 'SV-208935r603263_rule'
  tag stig_id: 'OL6-00-000259'
  tag gtitle: 'SRG-OS-000029'
  tag fix_id: 'F-9188r357786_fix'
  tag 'documentable'
  tag legacy: ['V-50827', 'SV-65033']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
