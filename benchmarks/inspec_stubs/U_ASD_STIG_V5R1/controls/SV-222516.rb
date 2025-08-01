control 'SV-222516' do
  title 'The application must prevent program execution in accordance with organization-defined policies regarding software program usage and restrictions, and/or rules authorizing the terms and conditions of software program usage.'
  desc 'Control of application execution is a mechanism used to prevent execution of unauthorized applications in order to follow the rules of least privilege. Some applications may provide a capability that runs counter to the mission or provides users with functionality that exceeds mission requirements.

Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). Removal of executable programs is not always possible; therefore, establishing a method of preventing program execution is critical to maintaining a secure system baseline.

Software program restrictions include restricting execution of programs in certain environments, while preventing execution in other environments; or limiting execution of certain application functionality based on organization-defined criteria (e.g., privileges, subnets, sandboxed environments, security managers, roles).'
  desc 'check', 'Review the application documentation and interview the application administrator to determine if policies, rules, or restrictions exist regarding application usage or terms which authorize the conditions of application use.

If the policy, terms, or conditions state there are no usage restrictions, this requirement is not applicable.

Interview the application administrator, review policy, terms, and conditions documents to determine what the terms and conditions of application usage are.

Have the application administrator demonstrate how the program execution is restricted in accordance with the policy terms and conditions. Typical methods include but are not limited to the use of Windows Group Policy, AppLocker, Software Restriction Policies, Java Security Manager, and Role-Based Access Control (RBAC).

If application requirements or policy documents specify application execution restriction requirements and the execution of the application or its subcomponents are not restricted in accordance with requirements or policy, this is a finding.'
  desc 'fix', 'Restrict application execution in accordance with the policy, terms, and conditions specified.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24186r493456_chk'
  tag severity: 'medium'
  tag gid: 'V-222516'
  tag rid: 'SV-222516r508029_rule'
  tag stig_id: 'APSC-DV-001480'
  tag gtitle: 'SRG-APP-000384'
  tag fix_id: 'F-24175r493457_fix'
  tag 'documentable'
  tag legacy: ['V-69515', 'SV-84137']
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
