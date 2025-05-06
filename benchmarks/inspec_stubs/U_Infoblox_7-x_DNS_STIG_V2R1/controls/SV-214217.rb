control 'SV-214217' do
  title 'The platform on which the name server software is hosted must be configured to send outgoing DNS messages from a random port.'
  desc "OS configuration practices as issued by the US Computer Emergency Response Team (US CERT) and the National Institute of Standards and Technology's (NIST's) National Vulnerability Database (NVD), based on identified vulnerabilities that pertain to the application profile into which the name server software fits, should be always followed. In particular, hosts that run the name server software should not provide any other services and therefore should be configured to respond to DNS traffic only. In other words, the only allowed incoming ports/protocols to these hosts should be 53/udp and 53/tcp. 

Outgoing DNS messages should be sent from a random port to minimize the risk of an attacker guessing the outgoing message port and sending forged replies."
  desc 'check', 'By default Infoblox systems utilize a random port for both DNS queries and notify messages.
Verify the default configuration is not overridden.

Navigate to Data Management >> DNS >> Members/Servers tab.

Review each server with the DNS service enabled.

Select each server, click "Edit", toggle Advanced Mode and select General >> Advanced tab.

Verify that the options under "Source Port Settings"; "Set static source UDP port for queries (not recommended)" and "Set static source UDP port for notify messages" use the default value of not enabled.

If configuration of either of these values exists, this is a finding.

When complete, click "Cancel" to exit the "Properties" screen.'
  desc 'fix', 'Navigate to Data Management >> DNS >> Grid DNS Properties.

Toggle Advanced Mode and select General >> Advanced tab.

Disable "Set static source UDP port for queries (not recommended)" and "Set static source UDP port for notify messages".

Navigate to Data Management >> DNS >> Members/Servers tab.

Review each Infoblox member with the DNS service enabled.

Select each server, click "Edit", toggle Advanced Mode and select General >> Advanced tab.

Locate the section labeled "Source port settings" and click "Override" to utilize the Grid default values that disable static source ports.
When complete, click "Save & Close" to save the changes and exit the "Properties" screen.

Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15432r295914_chk'
  tag severity: 'medium'
  tag gid: 'V-214217'
  tag rid: 'SV-214217r612370_rule'
  tag stig_id: 'IDNS-7X-000900'
  tag gtitle: 'SRG-APP-000516-DNS-000110'
  tag fix_id: 'F-15430r295915_fix'
  tag 'documentable'
  tag legacy: ['SV-83127', 'V-68637']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
