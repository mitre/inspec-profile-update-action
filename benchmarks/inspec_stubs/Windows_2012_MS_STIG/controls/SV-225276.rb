control 'SV-225276' do
  title 'The system must be configured to audit Account Logon - Credential Validation failures.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Credential validation records events related to validation tests on credentials for a user account logon.'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (V-14230) for the detailed auditing subcategories to be effective. 

Use the AuditPol tool to review the current Audit Policy configuration:
-Open a Command Prompt with elevated privileges ("Run as Administrator").
-Enter "AuditPol /get /category:*".

Compare the AuditPol settings with the following.  If the system does not audit the following, this is a finding.

Account Logon -> Credential Validation - Failure'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Account Logon -> "Audit Credential Validation" with "Failure" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-26975r471170_chk'
  tag severity: 'medium'
  tag gid: 'V-225276'
  tag rid: 'SV-225276r569185_rule'
  tag stig_id: 'WN12-AU-000002'
  tag gtitle: 'SRG-OS-000471-GPOS-00215'
  tag fix_id: 'F-26963r471171_fix'
  tag 'documentable'
  tag legacy: ['SV-53011', 'V-26530']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
