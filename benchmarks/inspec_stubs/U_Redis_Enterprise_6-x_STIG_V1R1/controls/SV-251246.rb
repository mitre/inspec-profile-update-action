control 'SV-251246' do
  title 'Redis Enterprise DBMS must prevent unauthorized and unintended information transfer via shared system resources.'
  desc 'The purpose of this control is to prevent information, including encrypted representations of information, produced by the actions of a prior user/role (or the actions of a process acting on behalf of a prior user/role) from being available to any current user/role (or current process) that obtains access to a shared system resource (e.g., registers, main memory, secondary storage) after the resource has been released back to the information system. Control of information in shared resources is also referred to as object reuse.

For more information, refer to:
https://redis.io/topics/acl more information on creating clearly defined categories and adding/editing users to categories and ACLs.
and
https://docs.redislabs.com/latest/rs/administering/access-control/user-roles/'
  desc 'check', 'Verify all returned users with security permissions are documented as requiring the permissions.

In the web UI, select access control >> Redis acls.

Verify that the documented users have the correct ACL(s) assigned to them by clicking the "Used By" link for each listed ACL.

Verify that all documented ACLs match each of the listed ACLs.

If "Redis ACL name" and "Used By" do not match the documentation, this is a finding.'
  desc 'fix', 'Users and ACLs can be created and modified from the Redis Enterprise UI by navigating to the access control tab as an admin user. Update the user roles and ACLs to reflect organizational requirements.'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54681r804926_chk'
  tag severity: 'medium'
  tag gid: 'V-251246'
  tag rid: 'SV-251246r804928_rule'
  tag stig_id: 'RD6X-00-011400'
  tag gtitle: 'SRG-APP-000243-DB-000373'
  tag fix_id: 'F-54635r804927_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
