control 'SV-224902' do
  title 'Windows Server 2016 must be configured to audit Policy Change - Authentication Policy Change successes.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Authentication Policy Change records events related to changes in authentication policy, including Kerberos policy and Trust changes.

'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (WN16-SO-000050) for the detailed auditing subcategories to be effective. 

Use the AuditPol tool to review the current Audit Policy configuration:

Open an elevated "Command Prompt" (run as administrator).

Enter "AuditPol /get /category:*".

Compare the AuditPol settings with the following.

If the system does not audit the following, this is a finding.

Policy Change >> Authentication Policy Change - Success'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Policy Change >> "Audit Authentication Policy Change" with "Success" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26593r465608_chk'
  tag severity: 'medium'
  tag gid: 'V-224902'
  tag rid: 'SV-224902r852312_rule'
  tag stig_id: 'WN16-AU-000330'
  tag gtitle: 'SRG-OS-000327-GPOS-00127'
  tag fix_id: 'F-26581r465609_fix'
  tag satisfies: ['SRG-OS-000327-GPOS-00127', 'SRG-OS-000064-GPOS-00033', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000466-GPOS-00210']
  tag 'documentable'
  tag legacy: ['SV-88117', 'V-73465']
  tag cci: ['CCI-000172', 'CCI-002234']
  tag nist: ['AU-12 c', 'AC-6 (9)']
end
