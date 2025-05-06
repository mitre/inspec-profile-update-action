control 'SV-254235' do
  title 'Nutanix AOS must implement address space layout randomization to protect its memory from unauthorized code execution.'
  desc 'Some adversaries launch attacks with the intent of executing code in nonexecutable regions of memory or in memory locations that are prohibited. Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can either be hardware-enforced or software-enforced with hardware providing the greater strength of mechanism.

Examples of attacks are buffer overflow attacks.'
  desc 'check', 'Confirm Nutanix AOS is configured to implement address space layout randomization.

$ sudo sysctl kernel.randomize_va_space
kernel.randomize_va_space = 2

If the value of kernel.randomize_va_space is anything other than "2", this is a finding.'
  desc 'fix', 'Configure Nutanix AOS to implement address space layout randomization by running the following command:

$ sudo sysctl kernel.randomize_va_space=2'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57720r846791_chk'
  tag severity: 'medium'
  tag gid: 'V-254235'
  tag rid: 'SV-254235r846793_rule'
  tag stig_id: 'NUTX-OS-001590'
  tag gtitle: 'SRG-OS-000433-GPOS-00193'
  tag fix_id: 'F-57671r846792_fix'
  tag 'documentable'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
