control 'SV-69201' do
  title 'The platform on which the name server software is hosted must be configured to respond to DNS traffic only.'
  desc "OS configuration practices as issued by the US Computer Emergency Response Team (US CERT) and the National Institute of Standards and Technology's (NIST's) National Vulnerability Database (NVD), based on identified vulnerabilities that pertain to the application profile into which the name server software fits, should be always followed. In particular, hosts that run the name server software should not provide any other services and therefore should be configured to respond to DNS traffic only. In other words, the only allowed incoming ports/protocols to these hosts should be 53/udp and 53/tcp. Outgoing DNS messages should be sent from a random port to minimize the risk of an attacker's guessing the outgoing message port and sending forged replies."
  desc 'check', 'Review the name server configuration. Verify the server is configured to only respond to incoming 53/udp and 53/tcp and any other ports and protocols required for the underlying platform to function normally, as specified by the related OS STIG.

If the DNS server is not configured to only respond to incoming 53/udp and 53/tcp and any other ports and protocols required for the underlying platform to function normally, as specified by the related OS STIG, this is a finding.'
  desc 'fix', 'Configure the DNS name server to only respond to incoming 53/udp and 53/tcp and any other ports and protocols required for the underlying platform to function normally, as specified by the related OS STIG.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55581r2_chk'
  tag severity: 'medium'
  tag gid: 'V-54955'
  tag rid: 'SV-69201r1_rule'
  tag stig_id: 'SRG-APP-000516-DNS-000109'
  tag gtitle: 'SRG-APP-000516-DNS-000109'
  tag fix_id: 'F-59817r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
