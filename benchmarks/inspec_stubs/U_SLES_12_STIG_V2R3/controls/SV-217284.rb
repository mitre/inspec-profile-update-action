control 'SV-217284' do
  title 'Address space layout randomization (ASLR) must be implemented by the SUSE operating system to protect memory from unauthorized code execution.'
  desc 'Some adversaries launch attacks with the intent of executing code in nonexecutable regions of memory or in memory locations that are prohibited. Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can either be hardware-enforced or software-enforced, with hardware providing the greater strength of mechanism.

Examples of attacks are buffer overflow attacks.'
  desc 'check', 'Verify the SUSE operating system implements ASLR.

Check that the SUSE operating system implements ASLR by running the following command:

> sudo sysctl kernel.randomize_va_space

kernel.randomize_va_space = 2

If the kernel parameter "randomize_va_space" is not equal to "2" or nothing is returned, this is a finding.'
  desc 'fix', %q(Configure the SUSE operating system to implement ASLR by running the following commands:

> sudo sysctl -w kernel.randomize_va_space=2

If "2" is not the system's default value, add or update the following line in "/etc/sysctl.d/99-stig.conf":

> sudo sh -c 'echo "kernel.randomize_va_space=2" >> /etc/sysctl.d/99-stig.conf'

> sudo sysctl --system)
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18512r646762_chk'
  tag severity: 'medium'
  tag gid: 'V-217284'
  tag rid: 'SV-217284r646764_rule'
  tag stig_id: 'SLES-12-030330'
  tag gtitle: 'SRG-OS-000433-GPOS-00193'
  tag fix_id: 'F-18510r646763_fix'
  tag 'documentable'
  tag legacy: ['SV-92177', 'V-77481']
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
