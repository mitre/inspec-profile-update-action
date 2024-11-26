control 'SV-253525' do
  title 'Prisma Cloud Compute Collections must be used to partition views and enforce organizational-defined need-to-know access.'
  desc 'Prisma Cloud Compute Collections are used to scope rules to target specific resources in an environment, partition views, and enforce which views specific users and groups can access. Collections can control access to data on a need-to-know basis.'
  desc 'check', "Navigate to Prisma Cloud Compute Console's >> Manage >> Collections and Tags >> Collections tab.

Review the Collections according to organizational policy. 

If no organizational-specific Collections are defined, this is a finding."
  desc 'fix', %q(Navigate to Prisma Cloud Compute Console's >> Manage >> Collections and Tags >> Collections tab.

Create a collection:
- Click "Add Collection".
- Enter a name and description and then specify a filter to target specific resources.
- Click "Save".)
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Prisma Cloud Compute'
  tag check_id: 'C-56977r840411_chk'
  tag severity: 'medium'
  tag gid: 'V-253525'
  tag rid: 'SV-253525r879533_rule'
  tag stig_id: 'CNTR-PC-000130'
  tag gtitle: 'SRG-APP-000038-CTR-000105'
  tag fix_id: 'F-56928r840412_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
