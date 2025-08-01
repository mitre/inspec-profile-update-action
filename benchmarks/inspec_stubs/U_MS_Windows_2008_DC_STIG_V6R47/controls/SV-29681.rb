control 'SV-29681' do
  title 'Users with Administrative privilege are not documented or do not have separate accounts for administrative duties and normal operational tasks.'
  desc 'Using a privileged account to perform routine functions makes the computer vulnerable to attack by any virus or Trojan Horse inadvertently introduced during a session that has been granted full privileges.

The rule of least privilege should always be enforced.'
  desc 'check', 'Ask the System Administrator (SA) to show the necessary documentation that identifies the members of this privileged group. 

This check verifies each user with administrative privileges has been assigned a unique account, separate from the built-in “Administrator” account.  This check also verifies the default “Administrator” account is not being used.  Administrators should be properly trained before being permitted to perform administrator duties. The IAO will maintain a list of all users belonging to the Administrator’s group. 

If any of the following conditions are true, then this is a finding:

•Each SA does not have a unique userid dedicated for administering the system.
•Each SA does not have a separate account for normal user tasks.
•The built-in administrator account is used to administer the system.
•Administrators have not been properly trained.
•The IAO does not maintain a list of users belonging to the Administrator’s group.'
  desc 'fix', 'Create the necessary documentation that identifies the members of this privileged group.  Ensure each member has a separate account for user duties and one for his privileged duties and the other requirements outlined in the manual check are met.'
  impact 0.7
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-7884r2_chk'
  tag severity: 'high'
  tag gid: 'V-1140'
  tag rid: 'SV-29681r2_rule'
  tag gtitle: 'Users with Administrative Privilege'
  tag fix_id: 'F-32r2_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
