control 'SV-207588' do
  title 'A BIND 9.x implementation operating in a split DNS configuration must be approved by the organizations Authorizing Official.'
  desc 'BIND 9.x has implemented an option to use "view" statements to allow for split DNS architecture to be configured on a single name server. 

If the split DNS architecture is improperly configured there is a risk that internal IP addresses and host names could leak into the external view of the DNS server. 

Allowing private IP space to leak into the public DNS system may provide a person with malicious intent the ability to footprint your network and identify potential attack targets residing on your private network.'
  desc 'check', 'If the BIND 9.x name server is not configured for split DNS, this is Not Applicable.

Verify that the split DNS implementation has been approved by the organizations Authorizing Official.

With the assistance of the DNS administrator, obtain the Authorizing Official’s letter of approval for the split DNS implementation.

If the split DNS implementation has not been approved by the organizations Authorizing Official, this is a finding.'
  desc 'fix', 'Obtain approval for the split DNS implementation from the Authorizing Official.'
  impact 0.7
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7843r283818_chk'
  tag severity: 'high'
  tag gid: 'V-207588'
  tag rid: 'SV-207588r612253_rule'
  tag stig_id: 'BIND-9X-001405'
  tag gtitle: 'SRG-APP-000516-DNS-000500'
  tag fix_id: 'F-7843r283819_fix'
  tag 'documentable'
  tag legacy: ['SV-87117', 'V-72493']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
