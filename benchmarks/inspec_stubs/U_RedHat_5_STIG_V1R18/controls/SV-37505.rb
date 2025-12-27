control 'SV-37505' do
  title "The SMTP service's SMTP greeting must not provide version information."
  desc 'The version of the SMTP service can be used by attackers to plan an attack based on vulnerabilities present in the specific version.'
  desc 'check', 'To check for the version of either sendmail or Postfix being displayed in the greeting:

# telnet localhost 25

If a version number is displayed, this is a finding.'
  desc 'fix', %q(Ensure sendmail or Postfix has been configured to mask the version information.

Procedure
for sendmail:
Edit the /etc/mail/sendmail.mc file to mask the veresion number by editing the line with "dnl" as follows:
define(`confSMTP_LOGIN_MSG', ` Mail Server Ready ; $b')dnl
rebuild the sendmail.cf file.

for Postfix:
Examine the "smtpd_banner" line of /etc/postfix/main.conf and remove any "$mail_version" entry on it or comment the entire "smtpd_banner" line to use the default value which does not display the version information.)
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36163r1_chk'
  tag severity: 'low'
  tag gid: 'V-4384'
  tag rid: 'SV-37505r2_rule'
  tag stig_id: 'GEN004560'
  tag gtitle: 'GEN004560'
  tag fix_id: 'F-31414r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
