control 'SV-69203' do
  title 'The platform on which the name server software is hosted must be configured to send outgoing DNS messages from a random port.'
  desc "OS configuration practices as issued by the US Computer Emergency Response Team (US CERT) and the National Institute of Standards and Technology's (NIST's) National Vulnerability Database (NVD), based on identified vulnerabilities that pertain to the application profile into which the name server software fits, should be always followed. In particular, hosts that run the name server software should not provide any other services and therefore should be configured to respond to DNS traffic only. In other words, the only allowed incoming ports/protocols to these hosts should be 53/udp and 53/tcp. 

Outgoing DNS messages should be sent from a random port to minimize the risk of an attacker guessing the outgoing message port and sending forged replies."
  desc 'check', 'Review the DNS configuration. Determine if a static port is being used to send outgoing DNS messages or whether it is configured to use a random port.

If the DNS configuration specifies a static port to be used for outgoing DNS messages rather than a random port, this is a finding.'
  desc 'fix', 'Configure the DNS server to use a random port for outgoing DNS messages.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55583r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54957'
  tag rid: 'SV-69203r1_rule'
  tag stig_id: 'SRG-APP-000516-DNS-000110'
  tag gtitle: 'SRG-APP-000516-DNS-000110'
  tag fix_id: 'F-59819r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
