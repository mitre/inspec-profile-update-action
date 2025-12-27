control 'SV-253533' do
  title 'Images stored within the container registry must contain only images to be run as containers within the container platform.'
  desc "The Prisma Cloud Compute Trusted Images feature allows the declaration, by policy, of which registries, repositories, and images to trust and how to respond when untrusted images are started in the organization's environment.

"
  desc 'check', %q(Navigate to Prisma Cloud Compute Console's >> Defend >> Compliance Trusted Images tab. 

Select the "Trust groups" tab.
If there is no Group, this is a finding. 

Select the "Policy" tab.
If the Trusted Images Rules is set to "off", this is a finding.

If a rule does not exist, this is a finding.

Click the three dots in the "Actions" column for rule. 
If the policy is disabled, this is a finding.

Click the policy row.
If the policy is not scoped to "All", this is a finding.)
  desc 'fix', %q(Navigate to Prisma Cloud Compute Console's >> Defend >> Compliance >> Trusted Images tab.  

Select the "Trust groups" tab.

Create a trusted group:
- Click "Add Group".
  Name: "IronBank"
- Specify a registry or repository: https://ironbank.dso.mil
- Click "Add to group".
- Specify a registry or repository: https://registry1.dso.mil/
(There are two group images total.)
- Click "Save".

Select the "Policy" tab.

Set the Trusted Images Rules to "on".

If a rule does not exist:
- Click "Add rule".
  Rule name = "IronBank"
  Scope = "All"

Allowed:
- Click "Select groups".
- Select "IronBank".
- Click "Apply".
- Keep all defaults and click "Save".

Enable policy:
- Click the "Default - alert all components" policy three-dot menu. 
- Set to "Enable".

Policy row scope:
- Click the policy rows.
- Change the policy scope to all images and containers within the intended monitored environment.
- Click "Save".)
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Prisma Cloud Compute'
  tag check_id: 'C-56985r840435_chk'
  tag severity: 'medium'
  tag gid: 'V-253533'
  tag rid: 'SV-253533r840437_rule'
  tag stig_id: 'CNTR-PC-000480'
  tag gtitle: 'SRG-APP-000141-CTR-000320'
  tag fix_id: 'F-56936r840436_fix'
  tag satisfies: ['SRG-APP-000141-CTR-000320', 'SRG-APP-000386-CTR-000920']
  tag 'documentable'
  tag cci: ['CCI-000381', 'CCI-001774']
  tag nist: ['CM-7 a', 'CM-7 (5) (b)']
end
