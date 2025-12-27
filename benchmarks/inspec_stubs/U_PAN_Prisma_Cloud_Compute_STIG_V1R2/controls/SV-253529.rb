control 'SV-253529' do
  title 'The configuration integrity of the container platform must be ensured and runtime policies must be configured.'
  desc "Prisma Cloud Compute's runtime defense is the set of features that provides both predictive and threat-based active protection for running containers.

Consistent application of Prisma Cloud Compute runtime policies ensures the continual application of policies and the associated effects. Prisma Cloud Compute's configurations must be monitored for configuration drift and addressed according to organizational policy.

"
  desc 'check', %q(Verify runtime policies are enabled. 

Navigate to Prisma Cloud Compute Console's Defend >> Runtime. 

Select "Container policy".
- If a rule does not exist, this is a finding. 
- If "Enable automatic runtime learning" is set to "off", this is a finding. 
- Click the three dots in the "Actions" column for the rule. 
- If the policy is disabled, this is a finding.
- Click the Container runtime policy. 
- If the policy is not scoped to "All", this is a finding.

Select the "App-Embedded policy" tab.
- If a rule does not exist, this is a finding.
- Click the three dots in the "Actions" column for rule "Default - alert on suspicious runtime behavior". 
- If the policy is disabled, this is a finding.
- Click the "Default - alert on suspicious runtime behavior" policy row. 
- If the "Default - alert on suspicious runtime behavior" policy is not scoped to "All", this is a finding.

Select the "Host policy" tab. 
- If a rule does not exist, this is a finding. 
- Click the three dots in the "Actions" column for the rule. 
- If the policy is disabled, this is a finding.
- Click the Host runtime policy. 
- If the policy is not scoped to "All", this is a finding.)
  desc 'fix', %q(Enable runtime policies. 

Navigate to Prisma Cloud Compute Console's Defend >> Runtime. 

Click the tab to be edited.

To add policy (for Host or App-Embedded policy):
- Click "Add rule". 
- Enter rule name.
  Scope = All
- Accept the defaults and click "Save".

To enable policy:
- Click the rule's three-dot menu. 
- Set to "Enable".

To change scope, click the rule row:
- Change the policy scope to "All".
- Click "Save".

To add container policy:
- Select the "Container policy" tab. 
- Set "Enable automatic runtime learning" to "On". 

To create a new runtime rule:
- Click "Add rule". 
- Configure the following settings:
  Enter rule name
  Scope = All

Select the "Anti-malware" tab.
Set the following:
- Prisma Cloud advanced threat protection = on
- Kubernetes attacks = on
- Suspicious queries to cloud provider APIs = on

Select the "Process" tab.
Set the following:
Process monitoring = enabled

Select the "Network" tab.
Set the following:
IP connectivity = enabled

Select the "File system" tab.
Set the following:
- File system monitoring = enabled
- Accept the defaults and click "Save".

Select the "App-Embedded policy" tab.
- Click the rule's three-dot menu. Set to "Enable".
- Click the rule name row.
- Change the scope to "All".
- Click "Save".

Create a new runtime rule:
- Click "add rule." 
- Enter rule name.
- Scope = All
- Accept the defaults and click "Save".

Select the "Host policy" tab.
- Click the rule's three-dot menu. Set to "Enable".
- Click the rule name row.
- Change the scope to "All".
- Click "Save".

- Click "Add rule". 
- Enter rule name.
- Scope = All
- Select the "Activities" tab.
- Set the following:
  Host activity monitoring ="Enabled"
  Docker commands = "On"
  New sessions spawned by sshd = "On"
  Commands run with sudo or su = "On"
  Log activity from background apps = "On"
  Track SSH events = "On"
- Accept the defaults and click "Save".)
  impact 0.7
  ref 'DPMS Target Palo Alto Networks Prisma Cloud Compute'
  tag check_id: 'C-56981r840423_chk'
  tag severity: 'high'
  tag gid: 'V-253529'
  tag rid: 'SV-253529r840425_rule'
  tag stig_id: 'CNTR-PC-000290'
  tag gtitle: 'SRG-APP-000101-CTR-000205'
  tag fix_id: 'F-56932r840424_fix'
  tag satisfies: ['SRG-APP-000101-CTR-000205', 'SRG-APP-000384-CTR-000915', 'SRG-APP-000447-CTR-001100', 'SRG-APP-000450-CTR-001105', 'SRG-APP-000507-CTR-001295', 'SRG-APP-000508-CTR-001300']
  tag 'documentable'
  tag cci: ['CCI-000135', 'CCI-000172', 'CCI-001764', 'CCI-002754', 'CCI-002824']
  tag nist: ['AU-3 (1)', 'AU-12 c', 'CM-7 (2)', 'SI-10 (3)', 'SI-16']
end
