control 'SV-234862' do
  title 'Address space layout randomization (ASLR) must be implemented by the SUSE operating system to protect memory from unauthorized code execution.'
  desc 'Some adversaries launch attacks with the intent of executing code in nonexecutable regions of memory or in memory locations that are prohibited. Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can either be hardware-enforced or software-enforced, with hardware providing the greater strength of mechanism.

Examples of attacks are buffer overflow attacks.'
  desc 'check', 'Verify the SUSE operating system implements ASLR.

Check that the SUSE operating system implements ASLR by running the following command:

> sudo sysctl kernel.randomize_va_space
Kernel.randomize_va_space = 2

If the kernel parameter "randomize_va_space" is not equal to "2" or nothing is returned, this is a finding.'
  desc 'fix', %q(Configure the SUSE operating system to implement ASLR by running the following command as an administrator:

> sudo sysctl -w kernel.randomize_va_space=2

If "2" is not the system's default value, add or update the following line in "/etc/sysctl.d/99-stig.conf":

> sudo sh -c 'echo "kernel.randomize_va_space=2" >> /etc/sysctl.d/99-stig.conf'

> sudo sysctl --system)
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38050r618855_chk'
  tag severity: 'medium'
  tag gid: 'V-234862'
  tag rid: 'SV-234862r622137_rule'
  tag stig_id: 'SLES-15-010550'
  tag gtitle: 'SRG-OS-000433-GPOS-00193'
  tag fix_id: 'F-38013r618856_fix'
  tag 'documentable'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
