control 'SV-218544' do
  title 'The SMTP service HELP command must not be enabled.'
  desc 'The HELP command should be disabled to mask version information.  The version of the SMTP service software could be used by attackers to target vulnerabilities present in specific software versions.'
  desc 'check', 'Check if Help is disabled. This rule is for "sendmail" only and not applicable to "Postfix".

Procedure:
# telnet localhost 25
> help

If the help command returns any sendmail version information, this is a finding. If sendmail is not installed, this check is not applicable.'
  desc 'fix', 'To disable the SMTP HELP command, clear the Sendmail help file.
# echo > /etc/mail/helpfile'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20019r555830_chk'
  tag severity: 'medium'
  tag gid: 'V-218544'
  tag rid: 'SV-218544r603259_rule'
  tag stig_id: 'GEN004540'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20017r555831_fix'
  tag 'documentable'
  tag legacy: ['V-12006', 'SV-63759']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
