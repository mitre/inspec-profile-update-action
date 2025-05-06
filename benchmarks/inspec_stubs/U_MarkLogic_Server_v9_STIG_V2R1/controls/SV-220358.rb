control 'SV-220358' do
  title 'MarkLogic Server objects (including but not limited to indexes, storage, functions, triggers, links to software external to the server, etc.) must be owned by database/MarkLogic Server principals authorized for ownership.'
  desc "Within the database, object ownership implies full privileges to the owned object, including the privilege to assign access to the owned objects to other subjects. Database functions and procedures can be coded using definer's rights. This allows anyone who utilizes the object to perform the actions if they were the owner. If not properly managed, this can lead to privileged actions being taken by unauthorized individuals.

Conversely, if critical tables or other objects rely on unauthorized owner accounts, these objects may be lost when an account is removed."
  desc 'check', 'Review system documentation to identify accounts authorized to own database objects. Review accounts that own objects in the database(s).

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Security icon.
2. Click the Users icon on the left tree menu.
3. Inspect the Users. If there is a User who is not authorized to own database objects, this is a finding.'
  desc 'fix', 'Assign ownership of authorized objects to authorized object owner accounts.

Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Security icon.
2. Click the Users icon on the left tree menu.
3. Inspect the Users. For users who are not authorized to own database objects, remove the users.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22073r401525_chk'
  tag severity: 'medium'
  tag gid: 'V-220358'
  tag rid: 'SV-220358r622777_rule'
  tag stig_id: 'ML09-00-002800'
  tag gtitle: 'SRG-APP-000133-DB-000200'
  tag fix_id: 'F-22062r401526_fix'
  tag 'documentable'
  tag legacy: ['SV-110063', 'V-100959']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
