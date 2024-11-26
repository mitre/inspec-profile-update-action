control 'SV-207483' do
  title 'The VMM must authenticate peripherals before establishing a connection.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

Peripherals include, but are not limited to, such devices as flash drives, external storage, and printers.

This requirement is applicable to devices capable of authentication.'
  desc 'check', 'Verify the VMM authenticates peripherals before establishing a connection.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to authenticate peripherals before establishing a connection.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7740r365853_chk'
  tag severity: 'medium'
  tag gid: 'V-207483'
  tag rid: 'SV-207483r854657_rule'
  tag stig_id: 'SRG-OS-000378-VMM-001540'
  tag gtitle: 'SRG-OS-000378'
  tag fix_id: 'F-7740r365854_fix'
  tag 'documentable'
  tag legacy: ['V-57167', 'SV-71427']
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
