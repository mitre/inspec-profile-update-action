control 'SV-238380' do
  title 'The Ubuntu operating system must disable the x86 Ctrl-Alt-Delete key sequence.'
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

Reload the daemon to take effect: 

# sudo systemctl daemon-reload'
  impact 0.7
  ref 'DPMS Target Canonical Ubuntu 20.04 LTS'
  tag check_id: 'C-41590r654313_chk'
  tag severity: 'high'
  tag gid: 'V-238380'
  tag rid: 'SV-238380r654315_rule'
  tag stig_id: 'UBTU-20-010460'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-41549r654314_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
