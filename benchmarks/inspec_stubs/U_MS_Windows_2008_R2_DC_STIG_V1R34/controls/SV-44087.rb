control 'SV-44087' do
  title 'The system must be configured to audit DS Access - Directory Service Access failures.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred as well as detecting attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Audit directory service access records events related to users accessing an Active Directory object.'
  desc 'check', 'Security Option “Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings” must be set to “Enabled” (V-14230) for the detailed auditing subcategories to be effective. 

Use the AuditPol tool to review the current Audit Policy configuration:
-Open a Command Prompt with elevated privileges (“Run as Administrator”).
-Enter “AuditPol /get /category:*”.

Compare the Auditpol settings with the following.  If the system does not audit the following, this is a finding:

DS Access -> Directory Service Access - Failure'
  desc 'fix', 'Detailed auditing subcategories are configured in Security Settings -> Advanced Audit Policy Configuration.   The summary level settings under Security Settings -> Local Policies -> Audit Policy will not be enforced (see V-14230).

Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> DS Access -> “Directory Service Access” with “Failure” selected.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-41815r1_chk'
  tag severity: 'medium'
  tag gid: 'V-33664'
  tag rid: 'SV-44087r1_rule'
  tag stig_id: 'WINAU-000452'
  tag gtitle: 'Audit - Directory Service Access - Failure'
  tag fix_id: 'F-37558r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-2, ECAR-3'
  tag cci: ['CCI-000172', 'CCI-002234']
  tag nist: ['AU-12 c', 'AC-6 (9)']
end
