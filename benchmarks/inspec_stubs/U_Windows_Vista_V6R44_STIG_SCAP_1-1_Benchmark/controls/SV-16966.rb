control 'SV-16966' do
  title 'Auditing must be configured as required.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.'
  desc 'fix', 'Configure the system to audit subcategories as outlined below.

Open a Command Prompt with elevated privileges. (Run as administrator).
Execute the following command for each subcategory.
Auditpol /set /subcategory:"subcategory name" /success:enable(disable) /failure:enable(disable)
(Include the quotes around the subcategory name).

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
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-6850'
  tag rid: 'SV-16966r3_rule'
  tag gtitle: 'Auditing Configuration'
  tag fix_id: 'F-71927r1_fix'
  tag 'documentable'
  tag third_party_tools: ['HK', 'HK']
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
