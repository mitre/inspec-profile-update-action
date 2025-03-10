control 'SV-93407' do
  title 'All Active Directory accounts synchronized with Tanium for non-privileged functions must be non-privileged domain accounts.'
  desc 'Tanium has the ability to synchronize with Active Directory for Tanium account management. Tanium advises that all replicated accounts for non-privileged level functions should be non-privileged domain accounts. In doing so, should a vulnerability in the industry standard OpenSSL libraries used by Tanium ever come to light, no privileged account information could be gained by an attacker. This is simply good housekeeping and should be exercised with any such platform product.'
  desc 'check', %q(Using a web browser on a system that has connectivity to Tanium, access the Tanium web user interface (UI) and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Administration".

Select the "Users" tab.

Review each of the users listed and determine their Active Directory synced account.

Access one of the domain's Active Directory Domain Controller servers with a Domain Administrator account.

Review each of the users for which a synced account is in the Tanium console as a user.

Validate whether any of the users are considered to be non-privileged in Active Directory, yet have privileged capabilities in Tanium.

If any of the non-privileged Active Directory accounts have elevated privileges and are synced as a Tanium privileged account, this is a finding.)
  desc 'fix', "Access one of the domain's Active Directory Domain Controller servers with a Domain Administrator account.

For each of the users for which a synced account is in the Tanium console as a privileged user, adjust the user to an appropriate security group in Active Directory.

Verify, after syncing with Tanium, the non-privileged user account is no longer in a privileged role within Tanium."
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78271r2_chk'
  tag severity: 'medium'
  tag gid: 'V-78701'
  tag rid: 'SV-93407r1_rule'
  tag stig_id: 'TANS-SV-000028'
  tag gtitle: 'SRG-APP-000340'
  tag fix_id: 'F-85437r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
