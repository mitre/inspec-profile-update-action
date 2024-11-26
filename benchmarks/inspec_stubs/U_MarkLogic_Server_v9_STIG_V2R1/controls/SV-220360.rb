control 'SV-220360' do
  title 'Unused database components, DBMS software, and database objects must be removed.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives. 

DBMSs must adhere to the principles of least functionality by providing only essential capabilities.'
  desc 'check', 'Review the list of components and features installed with MarkLogic, and check for unused components or features.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Databases icon.
2. Inspect the list of databases. If there is an unused database, this is a finding.
3. Click the Forests icon.
4. Inspect the list of forests. If there is an unused forest, this is a finding.
5. Click the Groups >> [GroupName] >> App Servers 
6. Inspect the list of app servers. If there is an unused database, this is a finding.'
  desc 'fix', 'Remove any database objects and applications that are installed to support them.

Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Databases icon.
2. Inspect the list of databases and select an unused database.
3. Click Delete and confirm the deletion.
4. Click the Forests icon.
5. Inspect the list of forests and select an unused forest.
6. Click Delete and confirm the deletion.
7. Click the Groups >> [GroupName] >> App Servers. 
8. Inspect the list of app servers and select an unused app server.
9. Click Delete and confirm the deletion.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22075r401531_chk'
  tag severity: 'medium'
  tag gid: 'V-220360'
  tag rid: 'SV-220360r622777_rule'
  tag stig_id: 'ML09-00-003100'
  tag gtitle: 'SRG-APP-000141-DB-000091'
  tag fix_id: 'F-22064r401532_fix'
  tag 'documentable'
  tag legacy: ['SV-110067', 'V-100963']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
