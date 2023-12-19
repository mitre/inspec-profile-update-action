control 'SV-240444' do
  title 'The SMTP service SMTP greeting must not provide version information.'
  desc 'The version of the SMTP service can be used by attackers to plan an attack based on vulnerabilities present in the specific version.'
  desc 'check', 'To check for the sendmail version being displayed in the greeting:

# more /etc/sendmail.cf | grep SmtpGreetingMessage

If it returns the following:

O SmtpGreetingMessage=$j Sendmail $v/$Z; $b

Then sendmail is providing version information, and this is a finding.'
  desc 'fix', 'Change the "O SmtpGreetingMessage" line in the /etc/sendmail.cf file to:

O SmtpGreetingMessage= Mail Server Ready ; $b'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43677r671071_chk'
  tag severity: 'medium'
  tag gid: 'V-240444'
  tag rid: 'SV-240444r671073_rule'
  tag stig_id: 'VRAU-SL-000615'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-43636r671072_fix'
  tag 'documentable'
  tag legacy: ['SV-100315', 'V-89665']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
