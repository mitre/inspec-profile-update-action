control 'SV-248869' do
  title 'The x86 Ctrl-Alt-Delete key sequence must be disabled on OL 8.'
  desc 'A locally logged-on user, who presses Ctrl-Alt-Delete when at the console, can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of system availability due to unintentional reboot. In a graphical user environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken.'
  desc 'check', 'Verify OL 8 is not configured to reboot the system when Ctrl-Alt-Delete is pressed with the following command: 
 
$ sudo systemctl status ctrl-alt-del.target | grep Loaded: 
 
Loaded: masked (Reason: Unit ctrl-alt-del.target is masked.)  
 
If the "ctrl-alt-del.target" Loaded: value is not set to "masked", this is a finding.'
  desc 'fix', 'Configure the system to disable the Ctrl-Alt-Delete sequence for the command line with the following command: 
 
$ sudo systemctl mask ctrl-alt-del.target 
 
Created symlink /etc/systemd/system/ctrl-alt-del.target -> /dev/null 
 
Reload the daemon to take effect: 
 
$ sudo systemctl daemon-reload'
  impact 0.7
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52303r780171_chk'
  tag severity: 'high'
  tag gid: 'V-248869'
  tag rid: 'SV-248869r780173_rule'
  tag stig_id: 'OL08-00-040170'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52257r780172_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
