control 'SV-255330' do
  title 'The audit information produced by Azure SQL Database must be protected from unauthorized read access.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. In addition, access to audit records provides information an attacker could potentially use to his or her advantage.  

To ensure the veracity of audit data, the information system and/or the application must protect audit information from any and all unauthorized access. This includes read, write, copy, etc.  

This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Some commonly employed methods include ensuring log files enjoy the proper file system permissions utilizing file system protections and limiting log data location. 

Additionally, applications with user interfaces to audit records must not allow the unfettered manipulation of or access to those records via the application. If the application provides access to the audit data, the application becomes accountable for ensuring that audit information is protected from unauthorized access. SQL Server is an application that is able to view and manipulate audit file data. 

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

'
  desc 'check', 'To obtain the Azure SQL Database audit file location(s), navigate to the Azure Portal, select the Azure SQL Database, then select "Auditing".

Review the storage settings for the audit.

Verify that the audit storage has the correct permissions by doing the following:
1. Review the Azure roles and users by navigating to the Azure Portal.
2. Review the Azure Server controlling the Azure SQL Database.
3. Select "Access Control (IAM)".
4. Select "Role assignments" and review the roles assigned to each user.
5. Select "Roles" and then select "View" under the "Details" column for each role.

Any roles or users with Read permissions to the auditing policy must be documented. If not documented, this is a finding.'
  desc 'fix', 'Modify audit permissions to meet the requirement to protect against unauthorized access.

To review the Azure roles and users, navigate to the Azure Portal and review the Azure Server controlling the Azure SQL Database.
1. Select "Access Control (IAM)".
2. Select "Role assignments" and review the roles assigned to each user.
3. Select "Roles", and then select "View" under the Details column for each role.
4. Remove any undocumented permissions or excessive read permissions to audit storage for user and roles.'
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-59003r877270_chk'
  tag severity: 'medium'
  tag gid: 'V-255330'
  tag rid: 'SV-255330r877270_rule'
  tag stig_id: 'ASQL-00-005900'
  tag gtitle: 'SRG-APP-000118-DB-000059'
  tag fix_id: 'F-58947r871115_fix'
  tag satisfies: ['SRG-APP-000118-DB-000059', 'SRG-APP-000121-DB-000202']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-001493']
  tag nist: ['AU-9 a', 'AU-9 a']
end
