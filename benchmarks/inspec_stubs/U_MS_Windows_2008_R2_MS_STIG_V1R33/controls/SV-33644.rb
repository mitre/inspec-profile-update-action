control 'SV-33644' do
  title 'The system will be configured to audit "Logon/Logoff -> Special Logon" successes.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred as well as detecting attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Special Logon records special logons which have administrative privileges and can be used to elevate processes.'
  desc 'check', 'Security Option “Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings” must be set to “Enabled” (V-14230) for the detailed auditing subcategories to be effective. 

Use the AuditPol tool to review the current Audit Policy configuration:
-Open a Command Prompt with elevated privileges (“Run as Administrator”).
-Enter “AuditPol /get /category:*”.

Compare the Auditpol settings with the following.  If the system does not audit the following, this is a finding:

Logon/Logoff -> Special Logon  - Success'
  desc 'fix', 'Detailed auditing subcategories are configured in Security Settings -> Advanced Audit Policy Configuration.   The summary level settings under Security Settings -> Local Policies -> Audit Policy will not be enforced (see V-14230).

Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Logon/Logoff -> "Audit Special Logon" with “Success” selected.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-34104r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26543'
  tag rid: 'SV-33644r1_rule'
  tag stig_id: 'WINAU-000509'
  tag gtitle: 'Audit - Special Logon - Success'
  tag fix_id: 'F-29784r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
