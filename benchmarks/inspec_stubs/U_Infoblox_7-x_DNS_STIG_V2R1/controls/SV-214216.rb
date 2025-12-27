control 'SV-214216' do
  title 'The platform on which the name server software is hosted must be configured to respond to DNS traffic only.'
  desc "OS configuration practices as issued by the US Computer Emergency Response Team (US CERT) and the National Institute of Standards and Technology's (NIST's) National Vulnerability Database (NVD), based on identified vulnerabilities that pertain to the application profile into which the name server software fits, should be always followed. In particular, hosts that run the name server software should not provide any other services and therefore should be configured to respond to DNS traffic only. In other words, the only allowed incoming ports/protocols to these hosts should be 53/udp and 53/tcp. Outgoing DNS messages should be sent from a random port to minimize the risk of an attacker's guessing the outgoing message port and sending forged replies."
  desc 'check', 'By default all services other than those required for management are disabled.

Review the Infoblox Grid for extra services turned on and turn them off. Configuration of Out of Band (OOB) management can be enabled to separate DNS from management traffic if desired.

Navigate to Grid >> Grid Manager >> Services tab.

Click on each service which is running and review the Service Status of each member.

If an external authoritative server is running any service other than DNS, this is a finding.'
  desc 'fix', 'Navigate to Grid >> Grid Manager >> Services tab.

Click on each service which is running and review the Service Status of each member.
Click on the member and select "Stop" to disable the unnecessary service.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15431r295911_chk'
  tag severity: 'medium'
  tag gid: 'V-214216'
  tag rid: 'SV-214216r612370_rule'
  tag stig_id: 'IDNS-7X-000890'
  tag gtitle: 'SRG-APP-000516-DNS-000109'
  tag fix_id: 'F-15429r295912_fix'
  tag 'documentable'
  tag legacy: ['SV-83129', 'V-68639']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
