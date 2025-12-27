control 'SV-253543' do
  title 'The configuration integrity of the container platform must be ensured and vulnerabilities policies must be configured.'
  desc "Prisma Cloud Compute's vulnerabilities defense is the set of features that provides both predictive and threat-based active protection for running containers.

Consistent application of Prisma Cloud Compute vulnerabilities policies ensures the continual application of policies and the associated effects. Prisma Cloud Compute's configurations must be monitored for configuration drift and addressed according to organizational policy.

"
  desc 'check', %q(To verify that vulnerabilities policies are enabled, navigate to Prisma Cloud Compute Console's Defend >> Vulnerabilities. 

Select the "Code repositories" tab.
For the "Repositories" and "CI" tab:
- If "Default - alert all components" does not exist, this is a finding. 
- Click the three dots in the "Actions" column for rule "Default - alert all components". 
- If the policy is disabled, this is a finding.
- Click the "Default - alert all components" policy row. 
- If "Default - alert all components" is not scoped to "All", this is a finding. 

Select the "Images" tab.
For the "CI" and "Deployed" tab:
- If "Default - alert all components" does not exist, this is a finding. 
- Click the three dots in the "Actions" column for rule "Default - alert all components". 
- If the policy is disabled, this is a finding.
- Click the "Default - alert all components" policy row. 
- If "Default - alert all components" is not scoped to "All", this is a finding.

Select the "Hosts" tab.
For the "Running hosts" and "VM images" tab:
- If the "Default - alert all components" does not exist, this is a finding. 
- Click the three dots in the "Actions" column for rule "Default - alert all components". 
- If the policy is disabled, this is a finding.
- Click the "Default - alert all components" policy row.
- If "Default - alert all components" is not scoped to "All", this is a finding. 

Select the "Functions" tab.
For the "Functions" and "CI" tab:
- If the "Default - alert all components" does not exist, this is a finding. 
- Click the three dots in the "Actions" column for rule "Default - alert all components".
- If the policy is disabled, this is a finding.
- Click the "Default - alert all components" policy row.
- If "Default - alert all components" is not scoped to "All", this is a finding.)
  desc 'fix', %q(To enable vulnerabilities policies, navigate to Prisma Cloud Compute Console's Defend >> Vulnerabilities. Click tab to be edited.

To add rule:
- Click "Add rule". 
- Enter rule name.
  Scope = All
- Accept the defaults and click "Save".

Click the rule three-dot menu. Set to "Enable".

Click the rule row:
- Change the policy scope to "All".
- Click "Save".)
  impact 0.7
  ref 'DPMS Target Palo Alto Networks Prisma Cloud Compute'
  tag check_id: 'C-56995r840465_chk'
  tag severity: 'high'
  tag gid: 'V-253543'
  tag rid: 'SV-253543r840467_rule'
  tag stig_id: 'CNTR-PC-001170'
  tag gtitle: 'SRG-APP-000384-CTR-000915'
  tag fix_id: 'F-56946r840466_fix'
  tag satisfies: ['SRG-APP-000384-CTR-000915', 'SRG-APP-000384-CTR-000915', 'SRG-APP-000456-CTR-001125', 'SRG-APP-000516-CTR-001335']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001764', 'CCI-002605']
  tag nist: ['CM-6 b', 'CM-7 (2)', 'SI-2 c']
end
