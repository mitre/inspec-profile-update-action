control 'SV-4342' do
  title 'The x86 CTRL-ALT-DELETE key sequence must be disabled.'
  desc 'Undesirable reboots can occur if the CTRL-ALT-DELETE key sequence is not disabled.  Such reboots may cause a loss of data or loss of access to critical information.'
  desc 'check', 'Verify that Linux systems have disabled the <CTRL><ALT><DELETE> key sequence by performing:

	# grep ctrlaltdel /etc/inittab

If the line returned is not commented out then this is a finding.'
  desc 'fix', 'Ensure that the CTRL-ALT-DELETE key sequence has been disabled.  If necessary, comment out the following line in the /etc/inittab file:
#ca::ctrlaltdel:/sbin/shutdown -t3 -r now'
  impact 0.7
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-2223r2_chk'
  tag severity: 'high'
  tag gid: 'V-4342'
  tag rid: 'SV-4342r2_rule'
  tag stig_id: 'GEN000000-LNX00580'
  tag gtitle: 'GEN000000-LNX00580'
  tag fix_id: 'F-4253r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
