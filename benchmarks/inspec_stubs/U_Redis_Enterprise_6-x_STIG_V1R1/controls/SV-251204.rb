control 'SV-251204' do
  title 'The audit information produced by Redis Enterprise DBMS must be protected from unauthorized deletion.'
  desc 'If audit data were to become compromised, competent forensic analysis and discovery of the true source of potentially malicious system activity would be impossible to achieve.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized deletion. This requirement can be achieved through multiple methods which will depend upon system architecture and design.

Some commonly employed methods include: ensuring log files enjoy the proper file system permissions utilizing file system protections; restricting access; and backing up log data to ensure log data is retained.

Applications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights the user enjoys in order make access decisions regarding the deletion of audit data.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

Deletion of database audit data could mask the theft of, or the unauthorized modification of, sensitive data stored in the database.'
  desc 'check', "To investigate the log files used by Redis Enterprise stored on the operating system, perform the following steps:
1. SSH into the server running Redis Enterprise.
2. Issue the command cd /var/opt/redislabs/log
3. Issue the command ls -ltr ./

Investigate the permissions on these files. These permissions should be 640 or 660 and assigned to the installation user and group or another appropriate group. 

If the permissions are readable by other or assigned an inappropriate owner/group, this is a finding.

Redis Enterprise does not support the ability to perform transaction logging.

Redis Enterprise also provides configurable role-based access control inherently within the product. This is available to users with the cluster viewer. To verify that users are provided the appropriate permissions that they are authorized to use, check each user's assigned roles.
1. Log in to Redis Enterprise.
2. Navigate to the access controls tab.
3. Navigate to the users tab.
4. Review all roles assigned to a user and verify that user is given the appropriate role for their authorization level. Roles with the Cluster Management Role of admin, cluster_member, cluster_viewer, or db_member are able to view logs in the UI.

If the user is not given the appropriate role, this is a finding."
  desc 'fix', "To investigate the log files used by Redis Enterprise, perform the following steps:
1. SSH into the server running Redis Enterprise.
2. Issue the command chmod 640 /var/opt/redislabs/log/* to change permissions of log files that are not appropriately assigned permissions.
3. Issue the command chown owner:group -R /var/opt/redislabs/log/ if the ownership is not correct where the owner and group are substituted for the appropriate owner and group.

Redis Enterprise provides configurable role-based access control inherently within the product. To ensure that users are provided the appropriate permissions that they are authorized to use, check each user's assigned roles.
1. Log in to Redis Enterprise.
2. Navigate to the access controls tab.
3. Navigate to the users tab.
4. Ensure that each user is given a role appropriate for their authorization level."
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54639r804800_chk'
  tag severity: 'medium'
  tag gid: 'V-251204'
  tag rid: 'SV-251204r804802_rule'
  tag stig_id: 'RD6X-00-006600'
  tag gtitle: 'SRG-APP-000120-DB-000061'
  tag fix_id: 'F-54593r804801_fix'
  tag 'documentable'
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
