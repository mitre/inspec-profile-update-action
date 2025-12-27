control 'SV-207394' do
  title 'The VMM must uniquely identify peripherals before establishing a connection.'
  desc 'Without identifying devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

Peripherals include, but are not limited to, such devices as flash drives, external storage, and printers, whether physical or virtual.'
  desc 'check', 'Verify the VMM uniquely identifies peripherals before establishing a connection.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to uniquely identify peripherals before establishing a connection.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7651r365592_chk'
  tag severity: 'medium'
  tag gid: 'V-207394'
  tag rid: 'SV-207394r378877_rule'
  tag stig_id: 'SRG-OS-000114-VMM-000580'
  tag gtitle: 'SRG-OS-000114'
  tag fix_id: 'F-7651r365593_fix'
  tag 'documentable'
  tag legacy: ['SV-71249', 'V-56989']
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
