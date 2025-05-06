control 'SV-254328' do
  title 'Windows Server 2022 must be configured to audit System - Other System Events failures.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Audit Other System Events records information related to cryptographic key operations and the Windows Firewall service.

'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (WN22-SO-000050) for the detailed auditing subcategories to be effective. 

Use the "AuditPol" tool to review the current Audit Policy configuration:

Open "PowerShell" or a "Command Prompt" with elevated privileges ("Run as administrator").

Enter "AuditPol /get /category:*"

Compare the "AuditPol" settings with the following:

If the system does not audit the following, this is a finding.

System >> Other System Events - Failure'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> System >> Audit Other System Events with "Failure" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57813r848798_chk'
  tag severity: 'medium'
  tag gid: 'V-254328'
  tag rid: 'SV-254328r848800_rule'
  tag stig_id: 'WN22-AU-000350'
  tag gtitle: 'SRG-OS-000327-GPOS-00127'
  tag fix_id: 'F-57764r848799_fix'
  tag satisfies: ['SRG-OS-000327-GPOS-00127', 'SRG-OS-000458-GPOS-00203', 'SRG-OS-000463-GPOS-00207', 'SRG-OS-000468-GPOS-00212']
  tag 'documentable'
  tag cci: ['CCI-000172', 'CCI-002234']
  tag nist: ['AU-12 c', 'AC-6 (9)']
end
