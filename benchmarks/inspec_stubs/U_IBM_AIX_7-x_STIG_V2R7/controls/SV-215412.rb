control 'SV-215412' do
  title 'If the AIX host is running an SMTP service, the SMTP greeting must not provide version information.'
  desc 'The version of the SMTP service can be used by attackers to plan an attack based on vulnerabilities present in the specific version.'
  desc 'check', 'If the AIX host is not running an SMTP service, this is Not Applicable.

Check the value of the "SmtpGreetingMessage" parameter in the "sendmail.cf" file:
# grep SmtpGreetingMessage /etc/mail/sendmail.cf

If the value of the "SmtpGreetingMessage" parameter contains the "$v" or "$Z" macros, this is a finding.'
  desc 'fix', 'Ensure "Sendmail" or its equivalent has been configured to mask the version information. If necessary, change the "O SmtpGreetingMessage" line in the "/etc/sendmail.cf" file from: 
O SmtpGreetingMessage=$j Sendmail $v/$Z; $b 

to: 

O SmtpGreetingMessage= Mail Server Ready ; $b'
  impact 0.3
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16610r294687_chk'
  tag severity: 'low'
  tag gid: 'V-215412'
  tag rid: 'SV-215412r508663_rule'
  tag stig_id: 'AIX7-00-003114'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16608r294688_fix'
  tag 'documentable'
  tag legacy: ['V-91653', 'SV-101751']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
