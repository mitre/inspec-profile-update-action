control 'SV-12507' do
  title 'The SMTP service HELP command must not be enabled.'
  desc 'The HELP command should be disabled to mask version information.  The version of the SMTP service software could be used by attackers to target vulnerabilities present in specific software versions.'
  desc 'check', 'Check if Help is disabled in Sendmail.

Procedure:
# telnet <host> 25
> help

If the help command returns any Sendmail version information, this is a finding.'
  desc 'fix', 'To disable the SMTP HELP command, remove or empty the Sendmail help file:
/etc/mail/helpfile.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-7970r2_chk'
  tag severity: 'medium'
  tag gid: 'V-12006'
  tag rid: 'SV-12507r2_rule'
  tag stig_id: 'GEN004540'
  tag gtitle: 'GEN004540'
  tag fix_id: 'F-11266r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
