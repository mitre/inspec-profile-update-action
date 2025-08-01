control 'SV-228565' do
  title 'The Oracle Linux operating system must be configured so the x86 Ctrl-Alt-Delete key sequence is disabled in the Graphical User Interface.'
  desc 'A locally logged-on user who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot. In the graphical environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken.'
  desc 'check', %q(Note: If the operating system does not have a graphical user interface installed, this requirement is Not Applicable.

Verify the operating system is not configured to reboot the system when Ctrl-Alt-Delete is pressed.

Check that the ctrl-alt-del.target is masked and not active in the graphical user interface with the following command:

# grep logout /etc/dconf/db/local.d/*

logout=''

If "logout" is not set to use two single quotations, or is missing, this is a finding.)
  desc 'fix', "Configure the system to disable the Ctrl-Alt-Delete sequence for the graphical user interface with the following command:

# touch /etc/dconf/db/local.d/00-disable-CAD 

Add the setting to disable the Ctrl-Alt-Delete sequence for the graphical user interface:

[org/gnome/settings-daemon/plugins/media-keys]
logout=''"
  impact 0.7
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-36331r602587_chk'
  tag severity: 'high'
  tag gid: 'V-228565'
  tag rid: 'SV-228565r603260_rule'
  tag stig_id: 'OL07-00-020231'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-36295r602588_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
