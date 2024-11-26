control 'SV-255332' do
  title 'The audit information produced by Azure SQL Database must be protected from unauthorized deletion.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized deletion. This requirement can be achieved through multiple methods which will depend upon system architecture and design.

Some commonly employed methods include: ensuring log files enjoy the proper file system permissions utilizing file system protections; restricting access; and backing up log data to ensure log data is retained.

Applications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights the user enjoys in order make access decisions regarding the deletion of audit data.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

Deletion of database audit data could mask the theft of, or the unauthorized modification of, sensitive data stored in the database.

'
  desc 'check', 'Obtain the Azure SQL Database audit file location(s) by navigating to the Azure Portal and selecting the Azure SQL Database, then selecting Auditing.

Review the storage settings for the audit.

Verify that the audit storage has the correct permissions by doing the following:
1. Navigate to the Azure Portal to review the Azure roles and users. 
2. Review the Azure Server controlling the Azure SQL Database.
3. Select "Access Control (IAM)".
4. Select "Role assignments" and review the roles assigned to each user.
5. Select "Roles", and then select "View" under the Details column for each role.

Any roles or users with Write permissions to the auditing policy must be documented. If not, this is a finding.'
  desc 'fix', 'Modify audit permissions to meet the requirement to protect against unauthorized access.

To review the Azure roles and users, navigate to the Azure Portal, and review the Azure Server controlling the Azure SQL Database.
1. Select "Access Control (IAM)".
2. Select "Role assignments" and review the roles assigned to each user.
3. Select "Roles", and then select "View" under the Details column for each role.
4. Remove any undocumented permissions or excessive read permissions to audit storage for user and roles.'
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-59005r877269_chk'
  tag severity: 'medium'
  tag gid: 'V-255332'
  tag rid: 'SV-255332r879578_rule'
  tag stig_id: 'ASQL-00-006100'
  tag gtitle: 'SRG-APP-000120-DB-000061'
  tag fix_id: 'F-58949r871121_fix'
  tag satisfies: ['SRG-APP-000120-DB-000061', 'SRG-APP-000122-DB-000203', 'SRG-APP-000123-DB-000204']
  tag 'documentable'
  tag cci: ['CCI-000164', 'CCI-001494', 'CCI-001495']
  tag nist: ['AU-9 a', 'AU-9', 'AU-9']
end
