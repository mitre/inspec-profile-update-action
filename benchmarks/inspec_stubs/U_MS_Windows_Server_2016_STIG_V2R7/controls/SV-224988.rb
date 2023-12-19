control 'SV-224988' do
  title 'Windows Server 2016 must be configured to audit DS Access - Directory Service Access failures.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Audit Directory Service Access records events related to users accessing an Active Directory object.

'
  desc 'check', 'This applies to domain controllers. It is NA for other systems.

Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (WN16-SO-000050) for the detailed auditing subcategories to be effective. 

Use the AuditPol tool to review the current Audit Policy configuration:

Open an elevated "Command Prompt" (run as administrator).

Enter "AuditPol /get /category:*".

Compare the AuditPol settings with the following. 

If the system does not audit the following, this is a finding.

DS Access >> Directory Service Access - Failure'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> DS Access >> "Directory Service Access" with "Failure" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26679r465866_chk'
  tag severity: 'medium'
  tag gid: 'V-224988'
  tag rid: 'SV-224988r852360_rule'
  tag stig_id: 'WN16-DC-000250'
  tag gtitle: 'SRG-OS-000327-GPOS-00127'
  tag fix_id: 'F-26667r465867_fix'
  tag satisfies: ['SRG-OS-000327-GPOS-00127', 'SRG-OS-000458-GPOS-00203', 'SRG-OS-000463-GPOS-00207', 'SRG-OS-000468-GPOS-00212']
  tag 'documentable'
  tag legacy: ['SV-88089', 'V-73437']
  tag cci: ['CCI-000172', 'CCI-002234']
  tag nist: ['AU-12 c', 'AC-6 (9)']
end
