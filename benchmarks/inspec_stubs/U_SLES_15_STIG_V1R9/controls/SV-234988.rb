control 'SV-234988' do
  title 'The SUSE operating system must disable the x86 Ctrl-Alt-Delete key sequence.'
  desc 'A locally logged-on user, who presses Ctrl-Alt-Delete when at the console, can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot. In the graphical user interface environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken.'
  desc 'check', 'Verify the SUSE operating system is not configured to reboot the system when Ctrl-Alt-Delete is pressed.

Check that the ctrl-alt-del.target is masked with the following command:

> systemctl status ctrl-alt-del.target
ctrl-alt-del.target
Loaded: masked (/dev/null; maksed)
Active: inactive (dead)

If the ctrl-alt-del.target is not masked, this is a finding.'
  desc 'fix', 'Configure the system to disable the Ctrl-Alt-Delete sequence for the command line with the following commands:

> sudo systemctl disable ctrl-alt-del.target

> sudo systemctl mask ctrl-alt-del.target

And reload the daemon to take effect 

> sudo systemctl daemon-reload'
  impact 0.7
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38176r619233_chk'
  tag severity: 'high'
  tag gid: 'V-234988'
  tag rid: 'SV-234988r622137_rule'
  tag stig_id: 'SLES-15-040060'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-38139r619234_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
