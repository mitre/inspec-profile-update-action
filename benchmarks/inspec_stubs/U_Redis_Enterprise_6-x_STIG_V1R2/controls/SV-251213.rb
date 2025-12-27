control 'SV-251213' do
  title 'The role(s)/group(s) used to modify database structure (including but not necessarily limited to tables, indexes, storage, etc.) and logic modules (stored procedures, functions, triggers, links to software external to Redis Enterprise DBMS, etc.) must be restricted to authorized users.'
  desc "If the DBMS were to allow any user to make changes to database structure or logic, those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.

Redis Enterprise provides configurable role-based access control inherently within the product. To ensure that users are provided the appropriate permissions that they are authorized to use, check each user's assigned roles."
  desc 'check', "To check each user's assigned role:
1. Log in to Redis Enterprise.
2. Navigate to the access controls tab.
3. Navigate to the users tab.
4. Review all roles assigned to a user and verify that user is given the appropriate role for their authorization level.

If the user is not given the appropriate role, this is a finding."
  desc 'fix', "To ensure that users are provided the appropriate permissions that they are authorized to use, check each user's assigned roles.
1. Log in to Redis Enterprise.
2. Navigate to the access controls tab.
3. Navigate to the users tab.
4. Locate desired user.
5. Assign appropriate permission based on desired authorization level."
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54648r804827_chk'
  tag severity: 'medium'
  tag gid: 'V-251213'
  tag rid: 'SV-251213r804950_rule'
  tag stig_id: 'RD6X-00-007700'
  tag gtitle: 'SRG-APP-000133-DB-000362'
  tag fix_id: 'F-54602r804828_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
