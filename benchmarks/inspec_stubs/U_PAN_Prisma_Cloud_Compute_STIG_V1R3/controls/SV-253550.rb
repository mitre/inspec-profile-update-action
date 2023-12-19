control 'SV-253550' do
  title "Prisma Cloud Compute's Intelligence Stream must be kept up to date."
  desc 'The Prisma Cloud Compute Console pulls the latest vulnerability and threat information from the Intelligence Stream (intelligence.twistlock.com). The Prisma Cloud Intelligence Stream provides timely vulnerability data collected and processed from a variety of certified upstream sources.'
  desc 'check', %q(Navigate to Prisma Cloud Compute Console's >> Manage >> System >> Intelligence tab. 

If the "Last streams update" date is older than 36 hours, this is a finding.)
  desc 'fix', "Prisma Cloud Compute Console's ability to communicate with the Intelligence Stream endpoint (https://intelligence.twistlock.com) dictates the method of vulnerability updates.

If the Console is able to communicate with the internet, ensure that intelligence.twistlock.com is resolvable, routable, and can establish a TLS session on TCP port 443.

If the Console is in an isolated environment and is unable to communicate with the internet, configure the Console to receive Intelligence Stream updates using one of the following methods:
- Manual import.
- Central console.
- HTTP/S distribution point.

https://docs.paloaltonetworks.com/prisma/prisma-cloud/22-01/prisma-cloud-compute-edition-admin/tools/update_intel_stream_offline.html"
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Prisma Cloud Compute'
  tag check_id: 'C-57002r840486_chk'
  tag severity: 'medium'
  tag gid: 'V-253550'
  tag rid: 'SV-253550r879827_rule'
  tag stig_id: 'CNTR-PC-001470'
  tag gtitle: 'SRG-APP-000456-CTR-001130'
  tag fix_id: 'F-56953r840487_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
