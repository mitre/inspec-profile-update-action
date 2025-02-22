control 'SV-71029' do
  title 'The operating system must uniquely identify peripherals before establishing a connection.'
  desc 'Without identifying devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

Peripherals include, but are not limited to, such devices as flash drives, external storage, and printers.'
  desc 'check', 'Verify the operating system uniquely identifies peripherals before establishing a connection. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to uniquely identify peripherals before establishing a connection.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57339r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56769'
  tag rid: 'SV-71029r1_rule'
  tag stig_id: 'SRG-OS-000114-GPOS-00059'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag fix_id: 'F-61665r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
