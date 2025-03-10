control 'SV-16967' do
  title 'Auditing records must be configured as required.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.'
  desc 'check', 'Verify the configuration of the audit subcategories listed below. The Auditpol.exe tool must be used to view the detailed audit policy.

Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" must be set to "Enabled" (V-14230) for the detailed auditing subcategories to be effective. The major audit categories in Local Policies will not be effective.

Open a Command Prompt with elevated privileges. (Run as administrator)
Enter "AuditPol /get /category:*".

If auditing is not configured for at least Success and/or Failure as listed below, this is a finding.
Subcategories not listed are not required but may be configured as needed by the site.

System
Security System Extension - Success and Failure
System Integrity - Success and Failure
IPSec Driver - Success and Failure
Security State Change - Success and Failure

Logon/Logoff
Logon - Success and Failure
Logoff - Success
Special Logon - Success

Privilege Use
Sensitive Privilege Use - Success and Failure

Detailed Tracking
Process Creation - Success

Policy Change
Audit Policy Change - Success and Failure
Authentication Policy Change - Success

Account Management
User Account Management - Success and Failure
Computer Account Management - Success and Failure
Security Group Management - Success and Failure
Other Account Management Events - Success and Failure

Account Logon
Credential Validation - Success and Failure'
  desc 'fix', 'Configure the system to audit subcategories as outlined below.

Open a Command Prompt with elevated privileges. (Run as administrator)
Execute the following command for each subcategory. 
Auditpol /set /subcategory:"subcategory name" /success:enable(disable) /failure:enable(disable)
(Include the quotes around the subcategory name.)

System
Security System Extension - Success and Failure
System Integrity - Success and Failure
IPSec Driver - Success and Failure
Security State Change - Success and Failure

Logon/Logoff
Logon - Success and Failure
Logoff - Success
Special Logon - Success

Privilege Use
Sensitive Privilege Use - Success and Failure

Detailed Tracking
Process Creation - Success

Policy Change
Audit Policy Change - Success and Failure
Authentication Policy Change - Success

Account Management
User Account Management - Success and Failure
Computer Account Management - Success and Failure
Security Group Management - Success and Failure
Other Account Management Events - Success and Failure

Account Logon
Credential Validation - Success and Failure'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-66501r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6850'
  tag rid: 'SV-16967r3_rule'
  tag stig_id: '4.008-MS'
  tag gtitle: 'Auditing Configuration'
  tag fix_id: 'F-71929r1_fix'
  tag 'documentable'
  tag third_party_tools: ['HK', 'HK']
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
