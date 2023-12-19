control 'SV-38885' do
  title 'The SMTP service HELP command must not be enabled.'
  desc 'The HELP command should be disabled to mask version information.  The version of the SMTP service software could be used by attackers to target vulnerabilities present in specific software versions.'
  desc 'check', 'Check to see if help is disabled in Sendmail.

Procedure:
# telnet <host> 25
help

If the help command returns any Sendmail version information, this is a finding.'
  desc 'fix', 'To disable the SMTP HELP command create an empty Sendmail help file.

# >  /etc/mail/help'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37886r1_chk'
  tag severity: 'medium'
  tag gid: 'V-12006'
  tag rid: 'SV-38885r1_rule'
  tag stig_id: 'GEN004540'
  tag gtitle: 'GEN004540'
  tag fix_id: 'F-31926r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
