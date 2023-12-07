control 'SV-254323' do
  title 'Windows Server 2022 must be configured to audit Privilege Use - Sensitive Privilege Use successes.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Sensitive Privilege Use records events related to use of sensitive privileges, such as "Act as part of the operating system" or "Debug programs".

'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (WN22-SO-000050) for the detailed auditing subcategories to be effective. 

Use the "AuditPol" tool to review the current Audit Policy configuration:

Open "PowerShell" or a "Command Prompt" with elevated privileges ("Run as administrator").

Enter "AuditPol /get /category:*"

Compare the "AuditPol" settings with the following:

If the system does not audit the following, this is a finding.

Privilege Use >> Sensitive Privilege Use - Success'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Privilege Use >> Audit Sensitive Privilege Use with "Success" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57808r848783_chk'
  tag severity: 'medium'
  tag gid: 'V-254323'
  tag rid: 'SV-254323r848785_rule'
  tag stig_id: 'WN22-AU-000300'
  tag gtitle: 'SRG-OS-000327-GPOS-00127'
  tag fix_id: 'F-57759r848784_fix'
  tag satisfies: ['SRG-OS-000327-GPOS-00127', 'SRG-OS-000064-GPOS-00033', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000466-GPOS-00210']
  tag 'documentable'
  tag cci: ['CCI-000172', 'CCI-002234']
  tag nist: ['AU-12 c', 'AC-6 (9)']
end
