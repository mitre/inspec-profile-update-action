control 'SV-252938' do
  title 'The systemd Ctrl-Alt-Delete burst key sequence in TOSS must be disabled.'
  desc 'A locally logged-on user who presses Ctrl-Alt-Delete when at the console can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot. In a graphical user environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken.'
  desc 'check', 'Verify TOSS is not configured to reboot the system when Ctrl-Alt-Delete is pressed seven times within two seconds with the following command:

$ sudo grep -i ctrl /etc/systemd/system.conf

CtrlAltDelBurstAction=none

If the "CtrlAltDelBurstAction" is not set to "none", commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure the system to disable the CtrlAltDelBurstAction by added or modifying the following line in the "/etc/systemd/system.conf" configuration file:

CtrlAltDelBurstAction=none

Reload the daemon for this change to take effect.

$ sudo systemctl daemon-reload'
  impact 0.7
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56391r824136_chk'
  tag severity: 'high'
  tag gid: 'V-252938'
  tag rid: 'SV-252938r824138_rule'
  tag stig_id: 'TOSS-04-010360'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56341r824137_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
