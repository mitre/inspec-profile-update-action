control 'SV-230931' do
  title 'Forescout must terminate the account of last resort password when members with access to the password leave the group.'
  desc 'A shared/group account credential is a shared form of authentication that allows multiple individuals to access the network device using a single account. If shared/group account credentials are not terminated when individuals leave the group, the user that left the group can still gain access even though they are no longer authorized. There may also be instances when specific user actions need to be performed on the network device without unique administrator identification or authentication. Examples of credentials include passwords and group membership certificates.'
  desc 'check', 'Review the documentation to verify a procedure exists to change the account of last resort and root account password when users with knowledge of the password leave the group.

If a procedure does not exist to change the account of last resort and root account password when users with knowledge of the password leave the group, this is a finding.'
  desc 'fix', 'Establish and document a procedure that requires the changing of the account of last resort and root account password when users with knowledge of the password leave the group. 

To change the password:
1. Log on to the Forescout Administrator UI.
2. From the menu, select Tools >> Options >> Console Preferences >> Password and Sessions.
3. Click the Password tab.
4. Click "User must change password at next logon if changed by admin user".
Note: the next time the account of last resort is accessed, the user will be prompted to change their password.

Note: Use of a cryptographically generated password is recommended. Password must be stored in a locked safe and used only when necessary since individual accounts are required to be used to ensure non-repudiation.'
  impact 0.5
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33861r603632_chk'
  tag severity: 'medium'
  tag gid: 'V-230931'
  tag rid: 'SV-230931r615886_rule'
  tag stig_id: 'FORE-NM-000020'
  tag gtitle: 'SRG-APP-000317-NDM-000282'
  tag fix_id: 'F-33834r603633_fix'
  tag 'documentable'
  tag cci: ['CCI-002142']
  tag nist: ['AC-2 (10)']
end
