control 'SV-253544' do
  title 'Prisma Cloud Compute must be configured to scan images that have not been instantiated as containers.'
  desc 'Prisma Cloud Compute ships with "only scan images with running containers" set to "on". To meet the requirements, "only scan images with running containers" must be set to "off" to disable or remove components that are not required.'
  desc 'check', %q(Navigate to Prisma Cloud Compute Console's >> Manage >> System >> Scan tab. 

Verify that for Running images, For Running images, "Only scan images with running containers" is set to "Off".

If "Only scan images with running containers" is set to "On", this is a finding.)
  desc 'fix', %q(Navigate to Prisma Cloud Compute Console's >> Manage >> System >> Scan tab. 

For Running images:
- Set "Only scan images with running containers" = "Off".
- Click "Save".)
  impact 0.7
  ref 'DPMS Target Palo Alto Networks Prisma Cloud Compute'
  tag check_id: 'C-56996r840468_chk'
  tag severity: 'high'
  tag gid: 'V-253544'
  tag rid: 'SV-253544r879757_rule'
  tag stig_id: 'CNTR-PC-001220'
  tag gtitle: 'SRG-APP-000384-CTR-000915'
  tag fix_id: 'F-56947r840469_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
