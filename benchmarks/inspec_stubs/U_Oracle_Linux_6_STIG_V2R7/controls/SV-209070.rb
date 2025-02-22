control 'SV-209070' do
  title 'The login user list must be disabled.'
  desc 'Leaving the user list enabled is a security risk since it allows anyone with physical access to the system to quickly enumerate known user accounts without logging in.'
  desc 'check', 'If the GConf2 package is not installed, this is not applicable.

To ensure the user list is disabled, run the following command:

$ gconftool-2 --direct \\
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \\
--get /apps/gdm/simple-greeter/disable_user_list

The output should be "true". If it is not, this is a finding.'
  desc 'fix', 'In the default graphical environment, users logging directly into the system are greeted with a login screen that displays all known users. This functionality should be disabled.

Run the following command to disable the user list:

$ sudo gconftool-2 --direct \\
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \\
--type bool --set /apps/gdm/simple-greeter/disable_user_list true'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9323r357995_chk'
  tag severity: 'medium'
  tag gid: 'V-209070'
  tag rid: 'SV-209070r793791_rule'
  tag stig_id: 'OL6-00-000527'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9323r357996_fix'
  tag 'documentable'
  tag legacy: ['V-59377', 'SV-73807']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
