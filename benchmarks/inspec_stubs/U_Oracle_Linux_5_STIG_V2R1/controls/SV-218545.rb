control 'SV-218545' do
  title 'The SMTP services SMTP greeting must not provide version information.'
  desc 'The version of the SMTP service can be used by attackers to plan an attack based on vulnerabilities present in the specific version.'
  desc 'check', 'To check for the version of either sendmail or Postfix being displayed in the greeting:

# telnet localhost 25

If a version number is displayed, this is a finding.'
  desc 'fix', 'Ensure sendmail or Postfix has been configured to mask the version information.

Procedure
for sendmail:
Change the O SmtpGreetingMessage line in the /etc/mail/sendmail.cf file as noted below:
O SmtpGreetingMessage=$j Sendmail $v/$Z; $b
change it to:
O SmtpGreetingMessage= Mail Server Ready ; $b

for Postfix:
Examine the "smtpd_banner" line of /etc/postfix/main.conf and remove any "$mail_version" entry on it or comment the entire "smtpd_banner" line to use the default value which does not display the version information.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20020r555833_chk'
  tag severity: 'low'
  tag gid: 'V-218545'
  tag rid: 'SV-218545r603259_rule'
  tag stig_id: 'GEN004560'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20018r555834_fix'
  tag 'documentable'
  tag legacy: ['V-4384', 'SV-63771']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
