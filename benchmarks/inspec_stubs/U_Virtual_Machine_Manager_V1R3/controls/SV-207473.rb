control 'SV-207473' do
  title 'The VMM must prevent use of service and helper VMs not required to support proper VMM function.'
  desc 'Control of program execution is a mechanism used to prevent execution of unauthorized programs. Some VMMs may provide a capability that runs counter to the mission or provides users with functionality that exceeds mission requirements. This includes functions and services installed at the VMM level.

Some of the service and helper VMs, installed by default, may be harmful or may not be necessary to support essential organizational operations (e.g., key missions, functions). Removal of such VMs is not always possible; therefore, establishing a method of preventing VM activation is critical to maintaining a secure system baseline.

Methods for complying with this requirement include restricting execution of VMs in certain environments, while preventing execution in other environments; or limiting execution of certain VM functionality based on organizationally defined criteria (e.g., privileges, subnets, sandboxed environments, or roles).'
  desc 'check', 'Verify the VMM prevents use of service and helper VMs not required to support proper VMM function.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to prevent use of service and helper VMs not required to support proper VMM function.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7730r365823_chk'
  tag severity: 'medium'
  tag gid: 'V-207473'
  tag rid: 'SV-207473r854647_rule'
  tag stig_id: 'SRG-OS-000368-VMM-001440'
  tag gtitle: 'SRG-OS-000368'
  tag fix_id: 'F-7730r365824_fix'
  tag 'documentable'
  tag legacy: ['V-57147', 'SV-71407']
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
