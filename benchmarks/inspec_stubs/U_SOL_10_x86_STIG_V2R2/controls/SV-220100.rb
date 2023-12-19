control 'SV-220100' do
  title 'The SMTP services SMTP greeting must not provide version information.'
  desc 'The version of the SMTP service can be used by attackers to plan an attack based on vulnerabilities present in the specific version.'
  desc 'check', 'Check for the Sendmail version being displayed in the greeting.

# telnet localhost 25

If a version number is displayed, this is a finding.

If telnet is unavailable for testing, check the value of the SmtpGreetingMessage parameter in the sendmail.cf file.

# grep SmtpGreetingMessage /etc/mail/sendmail.cf

If the value of the SmtpGreetingMessage parameter contains the $v or $Z macros, this is a finding.'
  desc 'fix', 'Ensure Sendmail or its equivalent has been configured to mask the version information. If necessary, change the O SmtpGreetingMessage line in the /etc/mail/sendmail.cf file as noted below.
O SmtpGreetingMessage=$j Sendmail $v/$Z; $b
Change it to:
O SmtpGreetingMessage= Mail Server Ready ; $b'
  impact 0.3
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-36429r602890_chk'
  tag severity: 'low'
  tag gid: 'V-220100'
  tag rid: 'SV-220100r603266_rule'
  tag stig_id: 'GEN004560'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-36393r602891_fix'
  tag 'documentable'
  tag legacy: ['V-4384', 'SV-42310']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
