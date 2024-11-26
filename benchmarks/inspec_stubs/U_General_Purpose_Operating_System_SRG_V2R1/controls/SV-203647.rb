control 'SV-203647' do
  title 'The operating system must uniquely identify peripherals before establishing a connection.'
  desc 'Without identifying devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

Peripherals include, but are not limited to, such devices as flash drives, external storage, and printers.'
  desc 'check', 'Verify the operating system uniquely identifies peripherals before establishing a connection. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to uniquely identify peripherals before establishing a connection.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3772r557186_chk'
  tag severity: 'medium'
  tag gid: 'V-203647'
  tag rid: 'SV-203647r557188_rule'
  tag stig_id: 'SRG-OS-000114-GPOS-00059'
  tag gtitle: 'SRG-OS-000114'
  tag fix_id: 'F-3772r557187_fix'
  tag 'documentable'
  tag legacy: ['SV-71029', 'V-56769']
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
