control 'SV-70983' do
  title 'The operating system must implement address space layout randomization to protect its memory from unauthorized code execution.'
  desc 'Some adversaries launch attacks with the intent of executing code in non-executable regions of memory or in memory locations that are prohibited. Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can either be hardware-enforced or software-enforced with hardware providing the greater strength of mechanism.

Examples of attacks are buffer overflow attacks.'
  desc 'check', 'Verify the operating system implements address space layout randomization to protect its memory from unauthorized code execution. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to implement address space layout randomization to protect its memory from unauthorized code execution.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57293r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56723'
  tag rid: 'SV-70983r1_rule'
  tag stig_id: 'SRG-OS-000433-GPOS-00193'
  tag gtitle: 'SRG-OS-000433-GPOS-00193'
  tag fix_id: 'F-61619r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
