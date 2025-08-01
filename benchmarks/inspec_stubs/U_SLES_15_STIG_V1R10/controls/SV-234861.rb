control 'SV-234861' do
  title 'The SUSE operating system must implement kptr-restrict to prevent the leaking of internal kernel addresses.'
  desc 'Some adversaries launch attacks with the intent of executing code in nonexecutable regions of memory or in memory locations that are prohibited. Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can either be hardware-enforced or software-enforced, with hardware providing the greater strength of mechanism.

Examples of attacks are buffer overflow attacks.'
  desc 'check', 'Verify the SUSE operating system prevents leaking of internal kernel addresses.

Check that the SUSE operating system prevents leaking of internal kernel addresses by running the following command:

> sudo sysctl kernel.kptr_restrict
kernel.kptr_restrict = 1

If the kernel parameter "kptr_restrict" is not equal to "1" or nothing is returned, this is a finding.'
  desc 'fix', %q(Configure the SUSE operating system to prevent leaking of internal kernel addresses by running the following command: 

> sudo sysctl -w kernel.kptr_restrict=1

If "1" is not the system's default value, add or update the following line in "/etc/sysctl.d/99-stig.conf":

> sudo sh -c 'echo "kernel.kptr_restrict=1" >> /etc/sysctl.d/99-stig.conf'

> sudo sysctl --system)
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38049r618852_chk'
  tag severity: 'medium'
  tag gid: 'V-234861'
  tag rid: 'SV-234861r854207_rule'
  tag stig_id: 'SLES-15-010540'
  tag gtitle: 'SRG-OS-000433-GPOS-00192'
  tag fix_id: 'F-38012r618853_fix'
  tag 'documentable'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
