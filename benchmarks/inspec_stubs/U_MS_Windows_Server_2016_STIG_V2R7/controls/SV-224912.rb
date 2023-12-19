control 'SV-224912' do
  title 'Windows Server 2016 must be configured to audit System - System Integrity successes.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

System Integrity records events related to violations of integrity to the security subsystem.

'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (WN16-SO-000050) for the detailed auditing subcategories to be effective. 

Use the AuditPol tool to review the current Audit Policy configuration:

Open an elevated "Command Prompt" (run as administrator).

Enter "AuditPol /get /category:*".

Compare the AuditPol settings with the following.

If the system does not audit the following, this is a finding.

System >> System Integrity - Success'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> System >> "Audit System Integrity" with "Success" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26603r465638_chk'
  tag severity: 'medium'
  tag gid: 'V-224912'
  tag rid: 'SV-224912r852322_rule'
  tag stig_id: 'WN16-AU-000440'
  tag gtitle: 'SRG-OS-000327-GPOS-00127'
  tag fix_id: 'F-26591r465639_fix'
  tag satisfies: ['SRG-OS-000327-GPOS-00127', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000471-GPOS-00216', 'SRG-OS-000477-GPOS-00222']
  tag 'documentable'
  tag legacy: ['SV-88141', 'V-73489']
  tag cci: ['CCI-000172', 'CCI-002234']
  tag nist: ['AU-12 c', 'AC-6 (9)']
end
