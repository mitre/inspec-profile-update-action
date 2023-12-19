control 'SRG-OS-000368-CLD-000140_rule' do
  title 'The Mission Owner of the IaaS/PaaS must remove orphaned or unused VM instances.'
  desc 'Control of program execution is a mechanism used to prevent execution of unauthorized programs. Some VMs may provide a capability that runs counter to the mission or provides users with functionality that exceeds mission requirements. This includes functions and services installed at the VM level.

Some of the service and helper VMs, installed by default, may be harmful or may not be necessary to support essential organizational operations (e.g., key missions, functions). Removal of such VMs is not always possible; therefore, establishing a method of preventing VM activation is critical to maintaining a secure system baseline.

Methods for complying with this requirement include restricting execution of VMs in certain environments, while preventing execution in other environments; or limiting execution of certain VM functionality based on organizationally defined criteria (e.g., privileges, subnets, sandboxed environments, or roles).'
  desc 'check', "If cloud VM's are managed by the CSP, verify separation requirements are addressed in the SLA.

Verify the IaaS/PaaS is configured to either disable or remove cloud services and helper VMs that are no longer required based on mission requirements.

If the IaaS/PaaS has not been disable or remove cloud services and helper VMs that are no longer required based on mission requirements, this is a finding."
  desc 'fix', "This applies to all Impact Levels.
FedRAMP Moderate, High.

For IaaS/PaaS, disable or remove cloud services and helper VMs that are no longer required based on mission requirements. Cloud services and VM's are added, removed, and updated by the cloud service portal management entity via the management plane."
  impact 0.5
  tag check_id: 'C-SRG-OS-000368-CLD-000140_chk'
  tag severity: 'medium'
  tag gid: 'SRG-OS-000368-CLD-000140'
  tag rid: 'SRG-OS-000368-CLD-000140_rule'
  tag stig_id: 'SRG-OS-000368-CLD-000140'
  tag gtitle: 'SRG-OS-000368-CLD-000140'
  tag fix_id: 'F-SRG-OS-000368-CLD-000140_fix'
  tag 'documentable'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
