control 'SV-24997' do
  title 'Users with administrative privilege must be documented and have separate accounts for administrative duties and normal operational tasks.'
  desc 'Using a privileged account to perform routine functions makes the computer vulnerable to malicious software inadvertently introduced during a session that has been granted full privileges.  The rule of least privilege must always be enforced.'
  desc 'check', 'Verify the following:

The necessary documentation that identifies members of the Administrators group exists with the ISSO.

Each user with administrative privileges has been assigned a unique administrator account, separate from the built-in "Administrator" account.

Each user with administrative privileges has a separate account for performing normal (non-administrative) functions.

Administrators must be properly trained before being permitted to perform administrator duties.

Use of the built-in Administrator account must not be allowed.

If any of these conditions are not met, this is a finding.'
  desc 'fix', 'Create necessary documentation that identifies members of the Administrators group, to be maintained with the ISSO.

Create unique administrator accounts, separate from the built-in "Administrator" account for each user with administrative privileges.

Create separate accounts for performing normal (non-administrative) functions for each user with administrative privileges.

Properly train users with administrative privileges.

Do not allow the use of  the built-in Administrator account.'
  impact 0.7
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-62059r2_chk'
  tag severity: 'high'
  tag gid: 'V-1140'
  tag rid: 'SV-24997r3_rule'
  tag gtitle: 'Users with Administrative Privilege'
  tag fix_id: 'F-66957r2_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
