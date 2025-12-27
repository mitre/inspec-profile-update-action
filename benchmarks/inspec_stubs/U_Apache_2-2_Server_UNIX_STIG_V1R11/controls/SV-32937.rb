control 'SV-32937' do
  title 'A public web server must limit email to outbound only.'
  desc 'Incoming E-mail has been known to provide hackers with access to servers. Disabling the incoming mail service prevents this type of attacks. Additionally, Email represents the main use of the Internet. It is specialized application that requires the dedication of server resources. To combine this type of transaction processing function with the file serving role of the web server creates an inherent conflict. Supporting mail services on a web server opens the server to the risk of abuse as an email relay.'
  desc 'check', '"To determine if email applications are excepting incoming connections (on standard ports)enter the following command:

telnet localhost 25

review the command results, If an e-mail program is installed and that program has been configured to accept inbound email, this is a finding."'
  desc 'fix', 'Configure the email application to not allow incoming connections.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33629r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2261'
  tag rid: 'SV-32937r1_rule'
  tag stig_id: 'WG330 A22'
  tag gtitle: 'WG330'
  tag fix_id: 'F-29266r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
