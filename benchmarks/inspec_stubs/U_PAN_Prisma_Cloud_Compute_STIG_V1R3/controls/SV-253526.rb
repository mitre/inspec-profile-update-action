control 'SV-253526' do
  title 'Prisma Cloud Compute Cloud Native Network Firewall (CNNF) automatically monitors layer 4 (TCP) intercontainer communications. Enforcement policies must be created.'
  desc 'Network segmentation and compartmentalization are important parts of a comprehensive defense-in-depth strategy. CNNF works as an east-west firewall for containers. It limits damage by preventing attackers from moving laterally through the environment when they have already compromised the perimeter.

'
  desc 'check', "Navigate to Prisma Cloud Compute Console's >> Radars >> Settings. 

If Container network monitoring is disabled, this is a finding.

If Host network monitoring is disabled, this is a finding."
  desc 'fix', %q(Navigate to Prisma Cloud Compute Console's >> Radars >> Settings. 

Set Container network monitoring to "enabled".

Set Host network monitoring to "enabled".)
  impact 0.7
  ref 'DPMS Target Palo Alto Networks Prisma Cloud Compute'
  tag check_id: 'C-56978r840414_chk'
  tag severity: 'high'
  tag gid: 'V-253526'
  tag rid: 'SV-253526r879534_rule'
  tag stig_id: 'CNTR-PC-000140'
  tag gtitle: 'SRG-APP-000039-CTR-000110'
  tag fix_id: 'F-56929r840415_fix'
  tag satisfies: ['SRG-APP-000039-CTR-000110', 'SRG-APP-000384-CTR-000915']
  tag 'documentable'
  tag cci: ['CCI-000381', 'CCI-001414']
  tag nist: ['CM-7 a', 'AC-4']
end
