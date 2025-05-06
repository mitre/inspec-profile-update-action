control 'SV-217159' do
  title 'The SUSE operating system must disable the x86 Ctrl-Alt-Delete key sequence.'
  desc 'A locally logged-on user who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot.'
  desc 'check', 'Verify the SUSE operating system is not configured to reboot the system when Ctrl-Alt-Delete is pressed.

Check that the ctrl-alt-del.target is masked with the following command:

> systemctl status ctrl-alt-del.target

Loaded: masked (/dev/null; masked)
Active: inactive (dead)

If the ctrl-alt-del.target is not masked, this is a finding.'
  desc 'fix', 'Configure the system to disable the Ctrl-Alt-Delete sequence for the command line with the following commands:

> sudo systemctl disable ctrl-alt-del.target

> sudo systemctl mask ctrl-alt-del.target

And reload the daemon to take effect 

> sudo systemctl daemon-reload'
  impact 0.7
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18387r646720_chk'
  tag severity: 'high'
  tag gid: 'V-217159'
  tag rid: 'SV-217159r646722_rule'
  tag stig_id: 'SLES-12-010610'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18385r646721_fix'
  tag 'documentable'
  tag legacy: ['SV-91867', 'V-77171']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
