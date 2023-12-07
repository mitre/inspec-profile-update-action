control 'SV-224884' do
  title 'Windows Server 2016 must be configured to audit Account Management - Security Group Management successes.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Security Group Management records events such as creating, deleting, or changing security groups, including changes in group members.

'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (WN16-SO-000050) for the detailed auditing subcategories to be effective. 

Use the AuditPol tool to review the current Audit Policy configuration:

Open an elevated "Command Prompt" (run as administrator).

Enter "AuditPol /get /category:*".

Compare the AuditPol settings with the following.

If the system does not audit the following, this is a finding.

Account Management >> Security Group Management - Success'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Account Management >> "Audit Security Group Management" with "Success" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26575r465554_chk'
  tag severity: 'medium'
  tag gid: 'V-224884'
  tag rid: 'SV-224884r852306_rule'
  tag stig_id: 'WN16-AU-000120'
  tag gtitle: 'SRG-OS-000004-GPOS-00004'
  tag fix_id: 'F-26563r465555_fix'
  tag satisfies: ['SRG-OS-000004-GPOS-00004', 'SRG-OS-000239-GPOS-00089', 'SRG-OS-000240-GPOS-00090', 'SRG-OS-000241-GPOS-00091', 'SRG-OS-000303-GPOS-00120', 'SRG-OS-000476-GPOS-00221']
  tag 'documentable'
  tag legacy: ['SV-88075', 'V-73423']
  tag cci: ['CCI-000018', 'CCI-000172', 'CCI-001403', 'CCI-001404', 'CCI-001405', 'CCI-002130']
  tag nist: ['AC-2 (4)', 'AU-12 c', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)']
end
