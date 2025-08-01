control 'SV-207504' do
  title 'The VMM must implement address space layout randomization to protect its memory from unauthorized code execution.'
  desc 'Some adversaries launch attacks with the intent of executing code in non-executable regions of memory or in memory locations that are prohibited. Data execution prevention safeguards can either be hardware-enforced or software-enforced with hardware providing the greater strength of mechanism.

Examples of attacks are buffer overflow attacks.'
  desc 'check', 'Verify the VMM implements address space layout randomization to protect its memory from unauthorized code execution.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to implement address space layout randomization to protect its memory from unauthorized code execution.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7761r365916_chk'
  tag severity: 'medium'
  tag gid: 'V-207504'
  tag rid: 'SV-207504r854678_rule'
  tag stig_id: 'SRG-OS-000433-VMM-001750'
  tag gtitle: 'SRG-OS-000433'
  tag fix_id: 'F-7761r365917_fix'
  tag 'documentable'
  tag legacy: ['V-57309', 'SV-71569']
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
