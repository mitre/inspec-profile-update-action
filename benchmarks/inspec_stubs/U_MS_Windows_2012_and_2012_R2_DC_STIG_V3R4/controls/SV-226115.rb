control 'SV-226115' do
  title 'Windows Server 2012/2012 R2 must be configured to audit System - Other System Events successes.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Audit Other System Events records information related to cryptographic key operations and the Windows Firewall service.

'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (V-14230) for the detailed auditing subcategories to be effective.

Use the AuditPol tool to review the current Audit Policy configuration:

Open an elevated "Command Prompt" (run as administrator).

Enter "AuditPol /get /category:*"

Compare the AuditPol settings with the following.

If the system does not audit the following, this is a finding.

System >> Other System Events - Success'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> System >> "Audit Other System Events" with "Success" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27817r475668_chk'
  tag severity: 'medium'
  tag gid: 'V-226115'
  tag rid: 'SV-226115r794290_rule'
  tag stig_id: 'WN12-AU-000105'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-27805r475669_fix'
  tag satisfies: ['SRG-OS-000458-GPOS-00203']
  tag 'documentable'
  tag legacy: ['SV-92773', 'V-78061']
  tag cci: ['CCI-000172', 'CCI-002234']
  tag nist: ['AU-12 c', 'AC-6 (9)']
end
