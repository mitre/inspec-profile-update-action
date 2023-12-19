control 'SV-255331' do
  title 'The audit information produced by Azure SQL Database must be protected from unauthorized modification.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. In addition, access to audit records provides information an attacker could potentially use to his or her advantage.  

To ensure the veracity of audit data, the information system and/or the application must protect audit information from any and all unauthorized access. This includes read, write, copy, etc.  

This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Some commonly employed methods include ensuring log files enjoy the proper file system permissions utilizing file system protections and limiting log data location. 

Additionally, applications with user interfaces to audit records should not allow for the unfettered manipulation of, or access to, those records via the application. If the application provides access to the audit data, the application becomes accountable for ensuring that audit information is protected from unauthorized access. SQL Server is an application that is able to view and manipulate audit file data. 

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.'
  desc 'check', 'Obtain the Azure SQL Database audit file location(s) by navigating to the Azure Portal and selecting the Azure SQL Database, then selecting Auditing.

Review the storage settings for the audit.

Verify that the audit storage has the correct permissions by doing the following:
1. Navigate to the Azure Portal to review the Azure roles and users. 
2. Review the Azure Server controlling the Azure SQL Database.
3. Select "Access Control (IAM)".
4. Select "Role assignments" and review the roles assigned to each user.
5. Select "Roles", and then select "View" under the Details column for each role.

Any roles or users with Write permissions to the auditing policy must be documented. If not, this is a finding.'
  desc 'fix', 'Modify audit permissions to meet the requirement to protect against unauthorized modification.

It is recommended to use immutable storage to prevent altering audits once created.

https://docs.microsoft.com/en-us/azure/storage/blobs/immutable-storage-overview

To review the Azure roles and users, navigate to the Azure Portal, and review the Azure Server controlling the Azure SQL Database.
1. Select "Access Control (IAM)".
2. Select "Role assignments" and review the roles assigned to each user.
3. Select "Roles", and then select "View" under the Details column for each role.
4. Remove any undocumented permissions or excessive write permissions to audit storage for user and roles.'
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-59004r877296_chk'
  tag severity: 'medium'
  tag gid: 'V-255331'
  tag rid: 'SV-255331r877296_rule'
  tag stig_id: 'ASQL-00-006000'
  tag gtitle: 'SRG-APP-000119-DB-000060'
  tag fix_id: 'F-58948r871118_fix'
  tag 'documentable'
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
