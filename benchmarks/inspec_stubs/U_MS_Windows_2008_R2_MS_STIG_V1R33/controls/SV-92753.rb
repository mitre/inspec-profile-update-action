control 'SV-92753' do
  title 'Windows Server 2008 R2 must be configured to audit Logon/Logoff - Account Lockout successes.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Account Lockout events can be used to identify potentially malicious logon attempts.'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (V-14230) for the detailed auditing subcategories to be effective.

Use the AuditPol tool to review the current Audit Policy configuration:

Open an elevated "Command Prompt" (run as administrator).

Enter "AuditPol /get /category:*"

Compare the AuditPol settings with the following. 

If the system does not audit the following, this is a finding.

Logon/Logoff >> Account Lockout - Success'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Logon/Logoff >> "Audit Account Lockout" with "Success" selected.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-77621r2_chk'
  tag severity: 'medium'
  tag gid: 'V-78057'
  tag rid: 'SV-92753r2_rule'
  tag stig_id: 'WINAU-000501'
  tag gtitle: 'WINAU-000501'
  tag fix_id: 'F-84769r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000172', 'CCI-001404']
  tag nist: ['AU-12 c', 'AC-2 (4)']
end
