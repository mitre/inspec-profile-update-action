control 'SV-33082' do
  title 'A public web server must limit e-mail to outbound only.'
  desc 'Incoming E-mail has been known to provide hackers with access to servers. Disabling the incoming mail service prevents this type of attacks. Additionally, Email represents the main use of the Internet. It is specialized application that requires the dedication of server resources. To combine this type of transaction processing function with the file serving role of the web server creates an inherent conflict. Supporting mail services on a web server opens the server to the risk of abuse as an email relay. This check verifies, by checking the OS, that incoming e-mail is not supported.'
  desc 'check', 'This check verifies, by checking the OS, that incoming e-mail is not supported.

Select START >> Programs >> Administrative Tools >> Services

Scroll down and review all the entries. If there is a mail program (SMTP service), then the reviewer must run that program to see if it will accept incoming e-mail (There are too many different programs for detailed instructions).

The reviewer should also check the Programs menu and sub-menus under start to see if there are any installed mail programs. The reviewer can also check the Add/Delete programs icon in the Control Panel to see if there are any e-mail programs installed. 

If there is an e-mail program installed and that program has been configured to accept inbound email, this is a finding.'
  desc 'fix', 'Isolate e-mail, if running on a public web server, to outbound e-mail only. This would allow the web-based application to send timely notices to users and administrators. On the SMTP or other e-mail server, the mail relay option must be disabled.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33752r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2261'
  tag rid: 'SV-33082r1_rule'
  tag stig_id: 'WG330 W22'
  tag gtitle: 'WG330'
  tag fix_id: 'F-29388r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
