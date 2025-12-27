control 'SV-203753' do
  title 'The operating system must implement non-executable data to protect its memory from unauthorized code execution.'
  desc 'Some adversaries launch attacks with the intent of executing code in non-executable regions of memory or in memory locations that are prohibited. Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can either be hardware-enforced or software-enforced with hardware providing the greater strength of mechanism.

Examples of attacks are buffer overflow attacks.'
  desc 'check', 'Verify the operating system implements non-executable data to protect its memory from unauthorized code execution. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to implement non-executable data to protect its memory from unauthorized code execution.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3878r375380_chk'
  tag severity: 'medium'
  tag gid: 'V-203753'
  tag rid: 'SV-203753r380206_rule'
  tag stig_id: 'SRG-OS-000433-GPOS-00192'
  tag gtitle: 'SRG-OS-000433'
  tag fix_id: 'F-3878r375381_fix'
  tag 'documentable'
  tag legacy: ['V-56725', 'SV-70985']
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
