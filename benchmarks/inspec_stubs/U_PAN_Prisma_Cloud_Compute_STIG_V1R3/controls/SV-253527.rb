control 'SV-253527' do
  title 'Prisma Cloud Compute Defender must be deployed to containerization nodes that are to be monitored.'
  desc 'Container platforms distribute workloads across several nodes. The ability to uniquely identify an event within an environment is critical. Prisma Cloud Compute Container Runtime audits record the time, container, corresponding image, and node where the event occurred.

'
  desc 'check', "Navigate to Prisma Cloud Compute Console's >> Manage >> Defenders >> Manage tab. 

Verify Prisma Cloud Compute Defenders have been deployed to all container runtime nodes to be monitored.

Review the list of deployed Defenders. If a Defender is missing, this is a finding."
  desc 'fix', "Navigate to Prisma Cloud Compute Console's >> Manage >> Defenders >> Manage tab. 

Deploy Defender to containerization node:
- Select the method of Defender deployment.
- Configure the Defender policy."
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Prisma Cloud Compute'
  tag check_id: 'C-56979r840417_chk'
  tag severity: 'medium'
  tag gid: 'V-253527'
  tag rid: 'SV-253527r879565_rule'
  tag stig_id: 'CNTR-PC-000240'
  tag gtitle: 'SRG-APP-000097-CTR-000180'
  tag fix_id: 'F-56930r840418_fix'
  tag satisfies: ['SRG-APP-000097-CTR-000180', 'SRG-APP-000100-CTR-000200']
  tag 'documentable'
  tag cci: ['CCI-000132', 'CCI-001487']
  tag nist: ['AU-3 c', 'AU-3 f']
end
