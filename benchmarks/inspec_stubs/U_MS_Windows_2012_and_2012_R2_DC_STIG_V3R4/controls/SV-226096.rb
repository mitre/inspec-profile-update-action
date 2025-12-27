control 'SV-226096' do
  title 'The system must be configured to audit DS Access - Directory Service Access failures.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detecting attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Audit directory service access records events related to users accessing an Active Directory object.'
  desc 'check', 'Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (V-14230) for the detailed auditing subcategories to be effective. 

Use the AuditPol tool to review the current Audit Policy configuration:
-Open a Command Prompt with elevated privileges ("Run as Administrator").
-Enter "AuditPol /get /category:*".

Compare the Auditpol settings with the following. If the system does not audit the following, this is a finding.

DS Access -> Directory Service Access - Failure'
  desc 'fix', 'Detailed auditing subcategories are configured in Security Settings -> Advanced Audit Policy Configuration. The summary level settings under Security Settings -> Local Policies -> Audit Policy will not be enforced (see V-14230).

Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> DS Access -> "Directory Service Access" with "Failure" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27798r475611_chk'
  tag severity: 'medium'
  tag gid: 'V-226096'
  tag rid: 'SV-226096r794784_rule'
  tag stig_id: 'WN12-AU-000032-DC'
  tag gtitle: 'SRG-OS-000471-GPOS-00215'
  tag fix_id: 'F-27786r794783_fix'
  tag 'documentable'
  tag legacy: ['SV-51152', 'V-33664']
  tag cci: ['CCI-000172', 'CCI-002234']
  tag nist: ['AU-12 c', 'AC-6 (9)']
end
