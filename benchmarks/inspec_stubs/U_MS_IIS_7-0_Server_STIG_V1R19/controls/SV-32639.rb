control 'SV-32639' do
  title 'A web server must limit e-mail to outbound only.'
  desc 'Incoming e-mails have been known to provide hackers with access to servers. Disabling the incoming mail service prevents this type of attacks. Additionally, e-mail is a specialized application requiring the dedication of server resources. A production web server should only provide hosting services for web-sites. Supporting mail services on a web server opens the server to the risk of abuse as an e-mail relay.'
  desc 'check', '1. Open the Task Manager.
2. Click the Services tab and look for SMTP service. If the service is running, then this is a finding.
3. Open Add/Remove Programs to see if there are any e-mail programs installed. Search the system to determine if other e-mail programs are running. If there is an e-mail program installed and that program has been configured to accept inbound e-mail, this is a finding.
4. If available, telnet to the server under review on port 25. If a response is received, this is a finding.'
  desc 'fix', '1. Disable the SMTP service. 
2. If other e-mail programs are running remove the programs.'
  impact 0.5
  ref 'DPMS Target IIS Installation 7'
  tag check_id: 'C-33495r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2261'
  tag rid: 'SV-32639r2_rule'
  tag stig_id: 'WG330 IIS7'
  tag gtitle: 'WG330'
  tag fix_id: 'F-29194r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
