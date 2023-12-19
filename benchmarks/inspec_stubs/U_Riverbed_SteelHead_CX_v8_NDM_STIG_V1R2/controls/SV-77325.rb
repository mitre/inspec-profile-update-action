control 'SV-77325' do
  title 'Riverbed Optimization System (RiOS) must terminate local shared/group account credentials, such as the Admin account is used, when members who know the account password leave the group.'
  desc "If shared/group account credentials are not terminated when individuals leave the group, the user that left the group can still gain access even though they are no longer authorized. 

A shared/group account credential is a shared form of authentication that allows multiple individuals to access the network device using a single account. There may also be instances when specific user actions need to be performed on the network device without unique administrator identification or authentication. Examples include system accounts, account of last resort, accounts used for testing/maintenance, and shared secrets that are configured on the administrator's workstation.

When users with knowledge of the account of last resort or default accounts are no longer authorized, account credentials must be changed in accordance with DoD policy."
  desc 'check', 'Verify RiOS is configured to protect the confidentiality and integrity of system information at rest.

Navigate to the Device Management Console
Set the "Username" to "admin"
Set the "Password" to "password"
Click "Log In"

If login occurs and administrative access is allowed, this is a finding.'
  desc 'fix', 'Configure RiOS to protect the confidentiality and integrity of system information at rest.

Navigate to the Device Management Console
Set the "Username" to "admin"
Set the "Password" to "password"
Click "Log In"

Navigate to Configure >> My Account
Select "Change Password"
Enter new password in "New Password:"
Enter new password in "Confirm New Password"
Click "Apply"
Navigate to the top right of the screen and click "Logout" to exit the current session

Navigate to the Device Management Console
Set the "Username" to "admin"
Set the "Password" to the new password
Click "Log In"
Verify that the administrator obtains access to the Device Management Console Home Page

Navigate to the top right of the screen and click "Logout" to exit the current session'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63629r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62835'
  tag rid: 'SV-77325r1_rule'
  tag stig_id: 'RICX-DM-000002'
  tag gtitle: 'SRG-APP-000317-NDM-000282'
  tag fix_id: 'F-68753r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002142']
  tag nist: ['AC-2 (10)']
end
