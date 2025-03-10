control 'SV-203730' do
  title 'The operating system must authenticate peripherals before establishing a connection.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

Peripherals include, but are not limited to, such devices as flash drives, external storage, and printers.'
  desc 'check', 'Verify the operating system authenticates peripherals before establishing a connection. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to authenticate peripherals before establishing a connection.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3855r375197_chk'
  tag severity: 'medium'
  tag gid: 'V-203730'
  tag rid: 'SV-203730r379921_rule'
  tag stig_id: 'SRG-OS-000378-GPOS-00163'
  tag gtitle: 'SRG-OS-000378'
  tag fix_id: 'F-3855r375198_fix'
  tag 'documentable'
  tag legacy: ['V-56809', 'SV-71069']
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
