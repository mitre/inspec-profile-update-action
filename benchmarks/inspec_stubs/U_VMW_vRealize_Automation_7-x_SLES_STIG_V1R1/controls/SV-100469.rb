control 'SV-100469' do
  title 'The SLES for vRealize must implement address space layout randomization to protect its memory from unauthorized code execution.'
  desc 'Some adversaries launch attacks with the intent of executing code in non-executable regions of memory or in memory locations that are prohibited. Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can either be hardware-enforced or software-enforced with hardware providing the greater strength of mechanism.

Examples of attacks are buffer overflow attacks.'
  desc 'check', 'Verify "randomize_va_space" has not been changed from the default "1" setting.

# sysctl kernel.randomize_va_space

If the return value is not "kernel.randomize_va_space = 1", this is a finding.'
  desc 'fix', 'Run the following command:

#sysctl kernel.randomize_va_space=1'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89511r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89819'
  tag rid: 'SV-100469r1_rule'
  tag stig_id: 'VRAU-SL-001340'
  tag gtitle: 'SRG-OS-000433-GPOS-00193'
  tag fix_id: 'F-96561r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
