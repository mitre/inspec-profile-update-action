control 'SV-220359' do
  title 'The role(s)/group(s) used to modify database structure (including but not necessarily limited to indexes, storage, etc.) and logic modules (functions, triggers, links to software external to the MarkLogic Server, etc.) must be restricted to authorized users.'
  desc 'If the DBMS were to allow any user to make changes to database structure or logic, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.'
  desc 'check', 'Identify the group(s)/role(s) established for MarkLogic modification and the list of users in those group(s)/roles.

Identify the individuals authorized to modify the DBMS.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Security icon.
2. Click the Users icon on the left tree menu.
3. Inspect the Users. If there is a User who is not authorized to own database objects, this is a finding.'
  desc 'fix', 'Revoke unauthorized memberships in the MarkLogic modification group(s)/role(s).

Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Security icon.
2. Click the Users icon on the left tree menu.
3. Inspect the Users. For users who are not authorized to own database objects, remove the users.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22074r401528_chk'
  tag severity: 'medium'
  tag gid: 'V-220359'
  tag rid: 'SV-220359r622777_rule'
  tag stig_id: 'ML09-00-002900'
  tag gtitle: 'SRG-APP-000133-DB-000362'
  tag fix_id: 'F-22063r401529_fix'
  tag 'documentable'
  tag legacy: ['SV-110065', 'V-100961']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
