control 'SV-218180' do
  title 'The x86 CTRL-ALT-DELETE key sequence must be disabled.'
  desc 'Undesirable reboots can occur if the CTRL-ALT-DELETE key sequence is not disabled.  Such reboots may cause a loss of data or loss of access to critical information.'
  desc 'check', 'Verify that reboot  using the CTRL-ALT-DELETE key sequence  has been disabled by performing:

# grep ctrlaltdel /etc/inittab

If the line returned does not specify "/usr/bin/logger", or is not commented out, this is a finding.'
  desc 'fix', 'Ensure the CTRL-ALT-DELETE key sequence has been disabled and attempts to use the sequence are logged.
In the /etc/inittab file replace:
ca::ctrlaltdel:/sbin/shutdown -t3 -r now
with
ca:nil:ctrlaltdel:/usr/bin/logger -p security.info "Ctrl-Alt-Del was pressed"

Once this change has been made, execute the following command to force the "init" daemon to re-read /etc/inittab:

# telinit q'
  impact 0.7
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19655r553877_chk'
  tag severity: 'high'
  tag gid: 'V-218180'
  tag rid: 'SV-218180r603259_rule'
  tag stig_id: 'GEN000000-LNX00580'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19653r553878_fix'
  tag 'documentable'
  tag legacy: ['V-4342', 'SV-62991']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
