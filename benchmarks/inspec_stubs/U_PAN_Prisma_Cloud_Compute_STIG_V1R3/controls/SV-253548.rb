control 'SV-253548' do
  title 'Prisma Cloud Compute must protect the confidentiality and integrity of transmitted information.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised since unprotected communications can be intercepted and either read or altered. 

Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.'
  desc 'check', %q(Navigate to Prisma Cloud Compute Console's >> Manage >> System >> General tab. 

Inspect the Telemetry section.

If "Share telemetry on product usage with Palo Alto Networks" is "On", this is a finding.

If "Allow admins and operators to upload logs to Customer Support directly from Console UI" is "On", this is a finding.)
  desc 'fix', %q(Navigate to Prisma Cloud Compute Console's >> Manage >> System >> General tab. 

In the Telemetry section:

Set "Share telemetry on product usage with Palo Alto Networks" to "Off". 

Set "Allow admins and operators to upload logs to Customer Support directly from Console UI" to "Off". 

Click "Save".)
  impact 0.7
  ref 'DPMS Target Palo Alto Networks Prisma Cloud Compute'
  tag check_id: 'C-57000r840480_chk'
  tag severity: 'high'
  tag gid: 'V-253548'
  tag rid: 'SV-253548r918216_rule'
  tag stig_id: 'CNTR-PC-001390'
  tag gtitle: 'SRG-APP-000439-CTR-001080'
  tag fix_id: 'F-56951r840481_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
