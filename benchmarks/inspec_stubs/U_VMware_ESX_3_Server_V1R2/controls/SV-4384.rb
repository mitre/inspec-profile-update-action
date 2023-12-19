control 'SV-4384' do
  title "The SMTP service's SMTP greeting must not provide version information."
  desc 'The version of the SMTP service can be used by attackers to plan an attack based on vulnerabilities present in the specific version.'
  desc 'check', 'Check for the Sendmail version being displayed in the greeting.

# telnet localhost 25

If a version number is displayed, this is a finding.'
  desc 'fix', 'Ensure Sendmail or its equivalent has been configured to mask the version information.  If necessary, change the O SmtpGreetingMessage line in the /etc/mail/sendmail.cf file as noted below.
    O SmtpGreetingMessage=$j Sendmail $v/$Z; $b
Change it to:
    O SmtpGreetingMessage= Mail Server Ready ; $b'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-8267r2_chk'
  tag severity: 'low'
  tag gid: 'V-4384'
  tag rid: 'SV-4384r2_rule'
  tag stig_id: 'GEN004560'
  tag gtitle: 'GEN004560'
  tag fix_id: 'F-4295r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
