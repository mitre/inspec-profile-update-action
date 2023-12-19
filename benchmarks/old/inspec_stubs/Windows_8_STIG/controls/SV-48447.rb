control 'SV-48447' do
  title 'The system must be configured to audit Logon/Logoff - Logon successes.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Logon records user logons. If this is an interactive logon, it is recorded on the local system. If it is to a network share, it is recorded on the system accessed.'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (V-14230) for the detailed auditing subcategories to be effective. 

Use the AuditPol tool to review the current Audit Policy configuration:
-Open a Command Prompt with elevated privileges ("Run as Administrator").
-Enter "AuditPol /get /category:*".

Compare the AuditPol settings with the following.  If the system does not audit the following, this is a finding:

Logon/Logoff -> Logon - Success'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Logon/Logoff -> "Audit Logon" with "Success" selected.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45110r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26541'
  tag rid: 'SV-48447r2_rule'
  tag stig_id: 'WN08-AU-000012'
  tag gtitle: 'Audit - Logon - Success'
  tag fix_id: 'F-41575r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECAR-2, ECAR-3'
  tag cci: ['CCI-000067', 'CCI-000172']
  tag nist: ['AC-17 (1)', 'AU-12 c']
end
