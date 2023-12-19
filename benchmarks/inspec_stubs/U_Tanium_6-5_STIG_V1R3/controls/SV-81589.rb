control 'SV-81589' do
  title 'All Active Directory accounts synchronized with Tanium must be non-privileged domain accounts.'
  desc 'Tanium has the ability to synchronize with Active Directory for Tanium account management. Tanium advises that all replicated accounts should be non-privileged domain accounts. In doing so, should a vulnerability in the industry standard OpenSSL libraries used by Tanium ever come to light, no privileged account information could be gained by an attacker. This is simply good housekeeping and should be exercised with any such platform product.'
  desc 'check', "Using a web browser on a system that has connectivity to the Tanium Server, access the Tanium Server web user interface (UI) and log on with CAC.

Click on the “Administration” tab.

Click on the “Users” tab.

Review each of the users listed and determine their Active Directory synced account.

Access one of the domain's Active Directory Domain Controller servers with a Domain Administrator account.

Review each of the Users for which a synced account is in the Tanium console as a user.

Validate whether any of the users have Domain Admin, Enterprise Admin, or any other elevated privileges in the domain.

If any of the Active Directory accounts have elevated privileges and are synced as a Tanium user account, this is a finding."
  desc 'fix', "Access one of the domain's Active Directory Domain Controller servers with a Domain Administrator account.

For each of the Users for which a synced account is in the Tanium console as a user and for which the account has elevated privileges, remove those accounts from the Tanium synced security group in Active Directory.

Verify, after syncing with Tanium, the user account is no longer in Tanium as a User."
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67735r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67099'
  tag rid: 'SV-81589r1_rule'
  tag stig_id: 'TANS-SV-000028'
  tag gtitle: 'SRG-APP-000340'
  tag fix_id: 'F-73199r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
