control 'SV-37504' do
  title 'The SMTP service HELP command must not be enabled.'
  desc 'The HELP command should be disabled to mask version information.  The version of the SMTP service software could be used by attackers to target vulnerabilities present in specific software versions.'
  desc 'check', 'Check if Help is disabled. This rule is for "sendmail" only and not applicable to "Postfix".

Procedure:
# telnet localhost 25
> help

If the help command returns any sendmail version information, this is a finding.  If sendmail is not installed this check is not applicable.'
  desc 'fix', 'To disable the SMTP HELP command, clear the Sendmail help file.
# echo -n > /etc/mail/helpfile'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36162r2_chk'
  tag severity: 'medium'
  tag gid: 'V-12006'
  tag rid: 'SV-37504r4_rule'
  tag stig_id: 'GEN004540'
  tag gtitle: 'GEN004540'
  tag fix_id: 'F-31413r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
