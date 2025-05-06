control 'SV-207474' do
  title 'The VMM must prevent inappropriate use of redundant guest VMs.'
  desc 'Control of program execution is a mechanism used to prevent execution of unauthorized programs. Some VMMs may provide a capability that runs counter to the mission or provides users with functionality that exceeds mission requirements. This includes functions and services installed at the VMM level. 

Some of the guest VMs, set up for redundancy, may be harmful or may not be necessary to support essential organizational operations (e.g., key missions, functions) at the present time. Removal of such VMs is not always possible; therefore, establishing a method of preventing VM activation is critical to maintaining a secure system baseline.

Methods for complying with this requirement include restricting execution of VMs in certain environments, while preventing execution in other environments; or limiting execution of certain VM functionality based on organizationally defined criteria (e.g., privileges, subnets, sandboxed environments, or roles).'
  desc 'check', 'Verify the VMM prevents inappropriate use of redundant guest VMs.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to prevent inappropriate use of redundant guest VMs.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7731r365826_chk'
  tag severity: 'medium'
  tag gid: 'V-207474'
  tag rid: 'SV-207474r854648_rule'
  tag stig_id: 'SRG-OS-000368-VMM-001450'
  tag gtitle: 'SRG-OS-000368'
  tag fix_id: 'F-7731r365827_fix'
  tag 'documentable'
  tag legacy: ['SV-71409', 'V-57149']
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
