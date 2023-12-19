control 'SV-45863' do
  title 'The SMTP service HELP command must not be enabled.'
  desc 'The HELP command should be disabled to mask version information.  The version of the SMTP service software could be used by attackers to target vulnerabilities present in specific software versions.'
  desc 'check', 'Check if the sendmail package is installed:
# rpm –q sendmail

If sendmail is not installed, this check is not applicable.  
Check if Help is disabled.  This rule is for “sendmail” only and not applicable to “Postfix”.

Procedure:
# telnet <host> 25
> help

If the help command returns any sendmail version information, this is a finding.'
  desc 'fix', 'To disable the SMTP HELP command, remove, rename or empty the /usr/lib/sendmail.d.helpfile file.

# echo > /usr/lib/sendmail.d/helpfile'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43159r1_chk'
  tag severity: 'medium'
  tag gid: 'V-12006'
  tag rid: 'SV-45863r2_rule'
  tag stig_id: 'GEN004540'
  tag gtitle: 'GEN004540'
  tag fix_id: 'F-39244r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
