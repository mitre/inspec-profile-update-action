control 'SV-221454' do
  title 'A public OHS installation must limit email to outbound only.'
  desc 'Incoming E-mail has been known to provide hackers with access to servers. Disabling the incoming mail service prevents this type of attacks. Additionally, Email represents the main use of the Internet. It is specialized application that requires the dedication of server resources. To combine this type of transaction processing function with the file serving role of the web server creates an inherent conflict. Supporting mail services on a web server opens the server to the risk of abuse as an email relay. This check verifies, by checking the OS, that incoming e-mail is not supported.'
  desc 'check', '1. Check whether the OHS server is configured to accept SMTP connections. (e.g., telnet localhost 25).

2. If it is, this is a finding.'
  desc 'fix', 'Configure the server to disallow inbound SMTP connections.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23169r415045_chk'
  tag severity: 'medium'
  tag gid: 'V-221454'
  tag rid: 'SV-221454r879887_rule'
  tag stig_id: 'OH12-1X-000217'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-23158r415046_fix'
  tag 'documentable'
  tag legacy: ['SV-79161', 'V-64671']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
