control 'SV-248870' do
  title 'The x86 Ctrl-Alt-Delete key sequence in OL 8 must be disabled if a graphical user interface is installed.'
  desc 'A locally logged-on user, who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot. In a graphical user environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken.'
  desc 'check', %q(Verify OL 8 is not configured to reboot the system when Ctrl-Alt-Delete is pressed when using a graphical user interface with the following command: 
 
$ sudo grep logout /etc/dconf/db/local.d/* 
 
logout='' 
 
If the "logout" key is bound to an action, is commented out, or is missing, this is a finding.)
  desc 'fix', %q(Configure the system to disable the Ctrl-Alt-Delete sequence when using a graphical user interface by creating or editing the "/etc/dconf/db/local.d/00-disable-CAD" file. 
 
Add the setting to disable the Ctrl-Alt-Delete sequence for a graphical user interface: 
 
[org/gnome/settings-daemon/plugins/media-keys] 
logout='' 
 
Update the dconf settings: 
 
$ sudo dconf update)
  impact 0.7
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52304r780174_chk'
  tag severity: 'high'
  tag gid: 'V-248870'
  tag rid: 'SV-248870r780176_rule'
  tag stig_id: 'OL08-00-040171'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52258r780175_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
