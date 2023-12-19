control 'SV-104515' do
  title 'Symantec ProxySG must use Role-Based Access Control (RBAC) to assign privileges to users for access to files and functions.'
  desc 'Organizations can create specific roles based on job functions and the authorizations (i.e., privileges) to perform needed operations on organizational information systems associated with the organization-defined roles. When administrators are assigned to the organizational roles, they inherit the authorizations or privileges defined for those roles. RBAC simplifies privilege administration for organizations because privileges are not assigned directly to every administrator (which can be a significant number of individuals for mid- to large-size organizations) but are instead acquired through role assignments. RBAC can be implemented either as a mandatory or discretionary form of access control.

The RBAC policies and the subjects and objects are defined uniquely for each network device, so they cannot be specified in the requirement.'
  desc 'check', 'Confirm that role-based access control is configured. 

1. Log on to the Management Console.
2. Click Configuration >> Policy >> Visual Policy Manager.
3. Click "Launch", select "Admin Access Layer" verify that at least one rule has been defined, and that each rule does not have "Any" or a single user defined in the "Source" field. Instead, each rule should have a user group specified in the "Source" field.
4. Confirm with the ProxySG administrator that each rule has the appropriate permission for the user or group specified in the rule (Action set to "Allow Read-Only Access" or "Allow Read-Write Access").

If Symantec ProxySG does not use Role-Based Access Control (RBAC) to assign privileges to users for access to files and functions, this is a finding.'
  desc 'fix', 'Configure the ProxySG for role-based group access.

1. Log on to the Web Management Console.
2. Click Configuration >> Policy >> Visual Policy Manager.
3. Click "Launch", select "Admin Access Layer". 
4. For each rule that does not have an Action of "None" or "Deny" that also does not have a user group set in the "Source" field, right-click the "Source" field and click "Set".
5. Click each "Source Object" that represents a specific user (vs a user group) and click "Remove".
6. Click "New" and select "Group" from the menu. Enter the correct information for the desired user group which should have access to the ProxySG and click "OK", then "OK" again. Repeat for each rule in the Admin Access layer.
7. Click the "Install Policy" button to commit the changes to the Symantec ProxySG.'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG NDM'
  tag check_id: 'C-93875r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94685'
  tag rid: 'SV-104515r1_rule'
  tag stig_id: 'SYMP-NM-000170'
  tag gtitle: 'SRG-APP-000329-NDM-000287'
  tag fix_id: 'F-100803r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002169']
  tag nist: ['CM-6 b', 'AC-3 (7)']
end
