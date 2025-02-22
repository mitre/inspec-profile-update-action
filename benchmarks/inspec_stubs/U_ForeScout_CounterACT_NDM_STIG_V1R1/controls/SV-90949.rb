control 'SV-90949' do
  title 'Administrative accounts for device management must be configured on the authentication server and not the network device itself (except for the account of last resort).'
  desc 'The use of authentication servers or other centralized management servers for providing centralized authentication services is required for network device management. Maintaining local administrator accounts for daily usage on each network device without centralized management is not scalable or feasible. Without centralized management, it is likely that credentials for some network devices will be forgotten, leading to delays in administration, which leads to delays in remediating production problems and addressing compromises in a timely fashion.

Administrative accounts for network device management must be configured on the authentication server and not the network device itself. This requirement does not apply to the account of last resort.'
  desc 'check', 'Review the CounterACT configuration to determine if administrative accounts for device management exist on the device other than the account of last resort and root account.

1. Log on to the CounterACT Administrator UI with admin or operator credentials.
2. From the menu, select Tools >> Options >> User Console and Options.
3. Select (highlight) the user profile to be reviewed (group or user) and then select "Edit".
4. Verify each user profile is for an approved administrator.
5. Verify each external LDAP group account profile by verifying on the trusted external directory group membership.

If any administrative accounts other than the account of last resort and root account exist on the device, this is a finding.'
  desc 'fix', 'Remove accounts that are not authorized. Do not remove the account of last resort.

1. Log on to the CounterACT Administrator UI with admin or operator credentials.
2. From the menu, select Tools >> Options >> User Console and Options.
3. Select (highlight) the user profile to be reviewed (group or user) and then select "Remove".
4. Remove external group membership, individual users on the Directory service.'
  impact 0.5
  ref 'DPMS Target ForeScout CounterACT NDM'
  tag check_id: 'C-75947r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76261'
  tag rid: 'SV-90949r1_rule'
  tag stig_id: 'CACT-NM-000012'
  tag gtitle: 'SRG-APP-000516-NDM-000336'
  tag fix_id: 'F-82897r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
