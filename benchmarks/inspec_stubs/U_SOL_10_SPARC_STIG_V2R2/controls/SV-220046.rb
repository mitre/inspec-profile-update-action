control 'SV-220046' do
  title 'The SMTP service HELP command must not be enabled.'
  desc 'The HELP command should be disabled to mask version information. The version of the SMTP service software could be used by attackers to target vulnerabilities present in specific software versions.'
  desc 'check', 'Check if Help is disabled in Sendmail.

Procedure:
# telnet <host> 25
> help

If the help command returns any Sendmail version information, this is a finding.

If telnet is unavailable for testing, check the value of the HelpFile parameter in the sendmail.cf file.

# grep HelpFile /etc/mail/sendmail.cf

If the contents of the file indicated by the HelpFile parameter contains any Sendmail version information, this is a finding.'
  desc 'fix', 'To disable the SMTP HELP command, clear the Sendmail help file.
# echo > /etc/mail/helpfile'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-21755r485132_chk'
  tag severity: 'medium'
  tag gid: 'V-220046'
  tag rid: 'SV-220046r603265_rule'
  tag stig_id: 'GEN004540'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21754r485133_fix'
  tag 'documentable'
  tag legacy: ['V-12006', 'SV-42309']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
