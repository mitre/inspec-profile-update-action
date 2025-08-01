control 'SV-35059' do
  title 'The SMTP service HELP command must not be enabled.'
  desc 'The HELP command should be disabled to mask version information.  The version of the SMTP service software could be used by attackers to target vulnerabilities present in specific software versions.'
  desc 'check', 'Verify that the Help command is disabled in Sendmail:

# ls -al /etc/mail/helpfile

If the file does not exist, this is not a finding.

If the help file does exist, verify that the file is empty:

# cat /etc/mail/helpfile

If the help file is not empty, this is a finding.'
  desc 'fix', 'To disable the SMTP HELP command, remove or empty the Sendmail help file:

/etc/mail/helpfile.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36569r2_chk'
  tag severity: 'medium'
  tag gid: 'V-12006'
  tag rid: 'SV-35059r2_rule'
  tag stig_id: 'GEN004540'
  tag gtitle: 'GEN004540'
  tag fix_id: 'F-11266r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
