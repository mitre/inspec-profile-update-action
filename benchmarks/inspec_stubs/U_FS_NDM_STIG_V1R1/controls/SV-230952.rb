control 'SV-230952' do
  title 'Forescout must be configured to use an authentication server for the purpose of authenticating users prior to granting administrative access.'
  desc "Centralized management of authentication settings increases the security of remote and nonlocal access methods. This control is particularly important protection against the insider threat. With robust centralized management, log records for administrator account access to the organization's network devices can be more readily analyzed for trends and anomalies. The alternative method of defining administrator accounts on each device exposes the device configuration to remote access authentication attacks and system administrators with multiple authenticators for each network device."
  desc 'check', 'Review the Forescout configuration to determine if administrative accounts for device management exist on the device other than the account of last resort and root account.

1. Log on to the Forescout Administrator UI with admin or operator credentials.
2. From the menu, select Tools >> Options >> Console Preferences.
3. Select (highlight) the user profile to be reviewed (group or user) and then select "Edit".
4. Verify each user profile is for an approved administrator.
5. Verify each external LDAP group account profile by verifying on the trusted external directory group membership.

If any administrative accounts other than the account of last resort and root account exist on the device, this is a finding.'
  desc 'fix', 'Remove accounts that are not authorized. Do not remove the account of last resort.

1. Log on to the Forescout Administrator UI with admin or operator credentials.
2. From the menu, select Tools >> Options >> Console Preferences.
3. Select (highlight) the user profile to be reviewed (group or user) and then select "Remove".
4. Remove external group membership, individual users on the Directory service.'
  impact 0.5
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33882r603695_chk'
  tag severity: 'medium'
  tag gid: 'V-230952'
  tag rid: 'SV-230952r615886_rule'
  tag stig_id: 'FORE-NM-000250'
  tag gtitle: 'SRG-APP-000516-NDM-000336'
  tag fix_id: 'F-33855r603696_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
