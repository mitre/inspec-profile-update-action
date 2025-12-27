control 'SV-253722' do
  title 'MariaDB must enforce discretionary access control policies, as defined by the data owner, over defined subjects, and objects.'
  desc 'Discretionary Access Control (DAC) is based on the notion that individual users are owners of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user-controlled table permissions.

When discretionary access control policies are implemented, subjects are not constrained with regard to what actions they can take with information for which they have already been granted access. Thus, subjects that have been granted access to information are not prevented from passing (i.e., the subjects have the discretion to pass) the information to other subjects or objects. 

A subject that is constrained in its operation by Mandatory Access Control policies is still able to operate under the less rigorous constraints of this requirement. Thus, while Mandatory Access Control imposes constraints preventing a subject from passing information to another subject operating at a different sensitivity level, this requirement permits the subject to pass the information to any subject at the same sensitivity level. 

The policy is bounded by the information system boundary. Once the information is passed outside of the control of the information system, additional means may be required to ensure the constraints remain in effect. While the older, more traditional definitions of discretionary access control require identity-based access control, that limitation is not required for this use of discretionary access control.'
  desc 'check', "Review system documentation to identify the required DAC.

Review the security configuration of the database and MariaDB. If applicable, review the security configuration of the application(s) using the database.

If the discretionary access control defined in the documentation is not implemented in the security configuration, this is a finding.
 
To check the permissions granted to a user use the following queries:
 
As the database administrator, run the following SQL:

**For user privileges:

Run this script to create the SHOW GRANTS script for each user: 

MariaDB> SELECT DISTINCT CONCAT( 'SHOW GRANTS FOR ', user,'@', host,';') AS grantQuery FROM mysql.user WHERE is_role = 'N';

Run each SHOW GRANTS command for each user.

Verify that all users have the correct privileges. If they do not, this is a finding.

**For role privileges (except admin_option, whether the role can be granted by a particular use):

MariaDB> SELECT CONCAT('SHOW GRANTS FOR ',Role,';' ) FROM mysql.roles_mapping;

Run each SHOW GRANTS command for each role.

Verify that all roles have the correct privileges. If they do not, this is a finding.
 
**To determine if a role has admin_option (Whether the role can be granted by a particular user)
 
MariaDB> SELECT * FROM mysql.roles_mapping;
 
Verify that all privileges are correct. If they are not, this is a finding."
  desc 'fix', "Implement the organization's DAC policy in the security configuration of the database and DBMS, and, if applicable, the security configuration of the application(s) using the database.
 
To grant and revoke privileges, as the database administrator, use the following SQL syntax:

**To Grant User and Role privileges:
 
MariaDB> GRANT  privilege  ON  database . table  TO  user|role ;
 
**To Revoke User and Role privileges:
 
MariaDB> REVOKE  privilege_type  ON   database . table  FROM  user|role ;"
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57174r841689_chk'
  tag severity: 'medium'
  tag gid: 'V-253722'
  tag rid: 'SV-253722r841691_rule'
  tag stig_id: 'MADB-10-006700'
  tag gtitle: 'SRG-APP-000328-DB-000301'
  tag fix_id: 'F-57125r841690_fix'
  tag 'documentable'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
