control 'SV-37327' do
  title 'The x86 CTRL-ALT-DELETE key sequence must be disabled.'
  desc 'Undesirable reboots can occur if the CTRL-ALT-DELETE key sequence is not disabled.  Such reboots may cause a loss of data or loss of access to critical information.'
  desc 'check', 'Verify that reboot  using the CTRL-ALT-DELETE key sequence  has been disabled by performing:

# grep ctrlaltdel /etc/inittab

If the line returned does not specify "/usr/bin/logger", or is not commented out, this is a finding.'
  desc 'fix', 'Ensure the CTRL-ALT-DELETE key sequence has been disabled and attempts to use the sequence are logged.
In the /etc/inittab file replace:
ca::ctrlaltdel:/sbin/shutdown -t3 -r now
with
ca:nil:ctrlaltdel:/usr/bin/logger -p security.info "Ctrl-Alt-Del was pressed"'
  impact 0.7
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36030r2_chk'
  tag severity: 'high'
  tag gid: 'V-4342'
  tag rid: 'SV-37327r1_rule'
  tag stig_id: 'GEN000000-LNX00580'
  tag gtitle: 'GEN000000-LNX00580'
  tag fix_id: 'F-31276r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
