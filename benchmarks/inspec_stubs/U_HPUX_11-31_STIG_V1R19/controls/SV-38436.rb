control 'SV-38436' do
  title "The SMTP service's SMTP greeting must not provide version information."
  desc 'The version of the SMTP service can be used by attackers to plan an attack based on vulnerabilities present in the specific version.'
  desc 'check', 'To check for the Sendmail version being displayed in the greeting:
# telnet localhost 25

If a version number is displayed, this is a finding.'
  desc 'fix', 'Ensure Sendmail or its equivalent has been configured to mask the version information. If necessary, change the O SmtpGreetingMessage line in the /etc/sendmail.cf file as noted below:
O SmtpGreetingMessage=$j Sendmail $v/$Z; $b
change it to:
O SmtpGreetingMessage= Mail Server Ready ; $b

Then restart the Sendmail service.'
  impact 0.3
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36570r1_chk'
  tag severity: 'low'
  tag gid: 'V-4384'
  tag rid: 'SV-38436r1_rule'
  tag stig_id: 'GEN004560'
  tag gtitle: 'GEN004560'
  tag fix_id: 'F-31938r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
