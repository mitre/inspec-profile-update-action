control 'SV-219706' do
  title 'System privileges granted using the WITH ADMIN OPTION must not be granted to unauthorized user accounts.'
  desc "The WITH ADMIN OPTION allows the grantee to grant a privilege to another database account. Best security practice restricts the privilege of assigning privileges to authorized personnel. Authorized personnel include DBAs, object owners, and, where designed and included in the application's functions, application administrators. Restricting privilege-granting functions to authorized accounts can help decrease mismanagement of privileges and wrongful assignments to unauthorized accounts."
  desc 'check', "Run the SQL query:

select grantee, privilege from dba_sys_privs
where grantee not in
(<list of non-applicable accounts>)
and admin_option = 'YES'
and grantee not in
(select grantee from dba_role_privs where granted_role = 'DBA');

(With respect to the list of special accounts that are excluded from this requirement, it is expected that the DBA will maintain the list to suit local circumstances, adding special accounts as necessary and removing any that are not supposed to be in use in the Oracle deployment that is under review.)

If any accounts that are not authorized to have the ADMIN OPTION are listed, this is a Finding."
  desc 'fix', 'Revoke assignment of privileges with the WITH ADMIN OPTION from unauthorized users and re-grant them without the option.

From SQL*Plus:

revoke [privilege name] from user [username];

Replace [privilege name] with the named privilege and [username] with the named user.

Restrict use of the WITH ADMIN OPTION to authorized administrators.

Document authorized privilege assignments with the WITH ADMIN OPTION in the System Security Plan.'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-21431r306967_chk'
  tag severity: 'medium'
  tag gid: 'V-219706'
  tag rid: 'SV-219706r401224_rule'
  tag stig_id: 'O112-BP-022300'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21430r306968_fix'
  tag 'documentable'
  tag legacy: ['SV-68223', 'V-53983']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
