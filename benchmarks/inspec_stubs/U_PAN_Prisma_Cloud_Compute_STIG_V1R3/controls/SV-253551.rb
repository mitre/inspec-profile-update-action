control 'SV-253551' do
  title 'Configuration of Prisma Cloud Compute must be continuously verified.'
  desc "Prisma Cloud Compute's configuration of Defender deployment must be monitored to ensure monitoring and protection of the environment is in accordance with organizational policy."
  desc 'check', %q(Navigate to Prisma Cloud Compute Console's >> Manage >> Defenders.

Select the "Manage" tab. Select the "Defenders" tab.

Determine the deployment status of the Defenders.

If a Defender is not deployed to intended workload(s) to be protected, this is a finding.)
  desc 'fix', %q(Navigate to Prisma Cloud Compute Console's >> Manage >> Defenders.

Select the "Manage" tab. Select the "Defenders" tab.

Deploy Defender to containerization node. Select the method of Defender deployment.

https://docs.paloaltonetworks.com/prisma/prisma-cloud/22-01/prisma-cloud-compute-edition-admin/install/defender_types.html)
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Prisma Cloud Compute'
  tag check_id: 'C-57003r840489_chk'
  tag severity: 'medium'
  tag gid: 'V-253551'
  tag rid: 'SV-253551r879844_rule'
  tag stig_id: 'CNTR-PC-001490'
  tag gtitle: 'SRG-APP-000473-CTR-001175'
  tag fix_id: 'F-56954r840490_fix'
  tag 'documentable'
  tag cci: ['CCI-002699']
  tag nist: ['SI-6 b']
end
