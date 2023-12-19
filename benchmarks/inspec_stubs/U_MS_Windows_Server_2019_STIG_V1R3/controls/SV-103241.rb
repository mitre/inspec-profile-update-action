control 'SV-103241' do
  title 'Windows Server 2019 must be configured to audit Account Logon - Credential Validation successes.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Credential Validation records events related to validation tests on credentials for a user account logon.'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (WN19-SO-000050) for the detailed auditing subcategories to be effective. 

Use the "AuditPol" tool to review the current Audit Policy configuration:

Open "PowerShell" or a "Command Prompt" with elevated privileges ("Run as administrator").

Enter "AuditPol /get /category:*"

Compare the "AuditPol" settings with the following:

If the system does not audit the following, this is a finding.

Account Logon >> Credential Validation - Success'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Account Logon >> "Audit Credential Validation" with "Success" selected.'
  impact 0.5
  ref 'DPMS Target Windows 2019'
  tag check_id: 'C-92471r1_chk'
  tag severity: 'medium'
  tag gid: 'V-93153'
  tag rid: 'SV-103241r1_rule'
  tag stig_id: 'WN19-AU-000070'
  tag gtitle: 'SRG-OS-000470-GPOS-00214'
  tag fix_id: 'F-99399r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
