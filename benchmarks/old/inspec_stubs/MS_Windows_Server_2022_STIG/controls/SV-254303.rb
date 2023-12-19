control 'SV-254303' do
  title 'Windows Server 2022 must be configured to audit Account Management - Security Group Management successes.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Security Group Management records events such as creating, deleting, or changing security groups, including changes in group members.

'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (WN22-SO-000050) for the detailed auditing subcategories to be effective. 

Use the "AuditPol" tool to review the current Audit Policy configuration:

Open "PowerShell" or a "Command Prompt" with elevated privileges ("Run as administrator").

Enter "AuditPol /get /category:*"

Compare the "AuditPol" settings with the following:

If the system does not audit the following, this is a finding.

Account Management >> Security Group Management - Success'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Account Management >>  Audit Security Group Management with "Success" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57788r848723_chk'
  tag severity: 'medium'
  tag gid: 'V-254303'
  tag rid: 'SV-254303r848725_rule'
  tag stig_id: 'WN22-AU-000100'
  tag gtitle: 'SRG-OS-000004-GPOS-00004'
  tag fix_id: 'F-57739r848724_fix'
  tag satisfies: ['SRG-OS-000004-GPOS-00004', 'SRG-OS-000239-GPOS-00089', 'SRG-OS-000240-GPOS-00090', 'SRG-OS-000241-GPOS-00091', 'SRG-OS-000303-GPOS-00120', 'SRG-OS-000476-GPOS-00221']
  tag 'documentable'
  tag cci: ['CCI-000018', 'CCI-000172', 'CCI-001403', 'CCI-001404', 'CCI-001405', 'CCI-002130']
  tag nist: ['AC-2 (4)', 'AU-12 c', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)']
end
