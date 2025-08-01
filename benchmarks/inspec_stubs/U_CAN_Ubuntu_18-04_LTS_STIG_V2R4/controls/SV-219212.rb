control 'SV-219212' do
  title 'The Ubuntu Operating system must disable the x86 Ctrl-Alt-Delete key sequence.'
  desc 'A locally logged-on user who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot.'
  desc 'check', 'Verify the Ubuntu operating system is not configured to reboot the system when Ctrl-Alt-Delete is pressed.

Check that the "ctrl-alt-del.target" (otherwise also known as reboot.target) is not active with the following command:

# systemctl status ctrl-alt-del.target
reboot.target - Reboot
 Loaded: loaded (/usr/lib/systemd/system/reboot.target; disabled)
 Active: inactive (dead)
 Docs: man:systemd.special(7)

If the "ctrl-alt-del.target" is active, this is a finding.'
  desc 'fix', 'Configure the system to disable the Ctrl-Alt-Delete sequence for the command line with the following command:

# sudo systemctl mask ctrl-alt-del.target

And reload the daemon to take effect 

# sudo systemctl daemon-reload'
  impact 0.7
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-20937r304964_chk'
  tag severity: 'high'
  tag gid: 'V-219212'
  tag rid: 'SV-219212r610963_rule'
  tag stig_id: 'UBTU-18-010151'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20936r304965_fix'
  tag 'documentable'
  tag legacy: ['V-100651', 'SV-109755']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
