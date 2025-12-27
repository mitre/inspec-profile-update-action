control 'SV-253532' do
  title 'The configuration integrity of the container platform must be ensured and compliance policies must be configured.'
  desc "Consistent application of Prisma Cloud Compute compliance policies ensures the continual application of policies and the associated effects. Prisma Cloud Compute's configurations must be monitored for configuration drift and addressed according to organizational policy.

"
  desc 'check', %q(Verify compliance policies are enabled.
 
Navigate to Prisma Cloud Compute Console's Defend >> Compliance. 

Select the "Code repositories" tab.
Select the "Repositories" and "CI" tab.
- If "Default – alert all components" does not exist, this is a finding. 
- Click the three dots in the "Actions" column for rule "Default - alert all components". 
- If the policy is disabled, this is a finding.
- Click the "Default – alert all components" policy row.
- If the "Default - alert on critical and high" policy is not scoped to "All", this is a finding. 

Select the "Containers and images" tab.
For the "Deployed" and "CI" tab:
- If the "Default - alert on critical and high" does not exist, this is a finding. 
- Click the three dots in the "Actions" column for rule "Default - alert on critical and high". 
- If the policy is disabled, this is a finding.
- Click the "Default - alert on critical and high" policy row.
- If the "Default - alert on critical and high" policy is not scoped to "All", this is a finding. 

Select the "Hosts" tab.
For the "Running hosts" and "VM images" tab:
- If the "Default - alert on critical and high" does not exist, this is a finding. 
- Click the three dots in the "Actions" column for rule "Default - alert on critical and high". 
- If the policy is disabled, this is a finding.
- Click the "Default - alert on critical and high" policy row.
- If the "Default - alert on critical and high" policy is not scoped to "All", this is a finding. 

Select the "Functions" tab.
For the "Functions" and "CI" tab:
- If the "Default – alert all components" does not exist, this is a finding. 
- Click the three dots in the "Actions" column for rule "Default -alert all components". 
- If the policy is disabled, this is a finding.
- Click the "Default - alert all components" policy row.
- If the "Default - alert on critical and high" policy is not scoped to "All", this is a finding.)
  desc 'fix', %q(Enable compliance policies.

Navigate to Prisma Cloud Compute Console's Defend >> Compliance and click tab to be edited.

To add rule:
- Click "Add rule." 
- Enter rule name.
  Scope = All
- Accept the defaults and click "Save".

Click the rule's three-dot menu. Set to "Enable".

Click the rule row.
- Change the policy scope to "All".
- Click "Save".)
  impact 0.7
  ref 'DPMS Target Palo Alto Networks Prisma Cloud Compute'
  tag check_id: 'C-56984r840432_chk'
  tag severity: 'high'
  tag gid: 'V-253532'
  tag rid: 'SV-253532r879586_rule'
  tag stig_id: 'CNTR-PC-000450'
  tag gtitle: 'SRG-APP-000133-CTR-000305'
  tag fix_id: 'F-56935r840433_fix'
  tag satisfies: ['SRG-APP-000133-CTR-000305', 'SRG-APP-000384-CTR-000915', 'SRG-APP-000435-CTR-001070', 'SRG-APP-000472-CTR-001170']
  tag 'documentable'
  tag cci: ['CCI-001499', 'CCI-001764', 'CCI-002385', 'CCI-002696']
  tag nist: ['CM-5 (6)', 'CM-7 (2)', 'SC-5 a', 'SI-6 a']
end
