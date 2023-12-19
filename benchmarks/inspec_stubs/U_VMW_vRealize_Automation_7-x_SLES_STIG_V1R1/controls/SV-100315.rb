control 'SV-100315' do
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
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89357r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89665'
  tag rid: 'SV-100315r1_rule'
  tag stig_id: 'VRAU-SL-000615'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-96407r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
