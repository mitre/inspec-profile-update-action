control 'SV-226094' do
  title 'Windows Server 2012/2012 R2 must be configured to audit Logon/Logoff - Account Lockout failures.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Account Lockout events can be used to identify potentially malicious logon attempts.'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (V-14230) for the detailed auditing subcategories to be effective.

Use the AuditPol tool to review the current Audit Policy configuration:

Open an elevated "Command Prompt" (run as administrator).

Enter "AuditPol /get /category:*"

Compare the AuditPol settings with the following. If the system does not audit the following, this is a finding.

Logon/Logoff >> Account Lockout - Failure'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Logon/Logoff >> "Audit Account Lockout" with "Failure" selected.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27796r475605_chk'
  tag severity: 'medium'
  tag gid: 'V-226094'
  tag rid: 'SV-226094r569184_rule'
  tag stig_id: 'WN12-AU-000031'
  tag gtitle: 'SRG-OS-000474-GPOS-00219'
  tag fix_id: 'F-27784r475606_fix'
  tag 'documentable'
  tag legacy: ['SV-92769', 'V-78059']
  tag cci: ['CCI-000172', 'CCI-001404']
  tag nist: ['AU-12 c', 'AC-2 (4)']
end
