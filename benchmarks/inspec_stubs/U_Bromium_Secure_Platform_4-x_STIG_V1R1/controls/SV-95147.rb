control 'SV-95147' do
  title 'The Bromium Enterprise Controller (BEC) must change the password for the Account of Last Resort when an individual with knowledge of the password leaves the group.'
  desc 'If shared/group account credentials are not terminated when individuals leave the group, the user who left the group can still gain access even though they are no longer authorized. A shared/group account credential is a shared form of authentication that allows multiple individuals to access the application using a single account. There may also be instances when specific user actions need to be performed on the information system without unique user identification or authentication. Examples of credentials include passwords and group membership certificates.

Note: Other passwords that should be considered for rotation or changes include the password to decrypt the malware manifest and the service account used to connect BEC to SQL Server.-Note: If the Account of Last Resort has been removed after installation and configuration per vendor-recommended best practice, there is no need to rotate this password.  

Note: If the Account of Last Resort has been removed after installation and configuration per vendor-recommended best practice, there is no need to rotate this password.'
  desc 'check', "If the Account of Last Resort has been removed after installation and configuration per vendor-recommended best practice (BROM-00-000300), this is not a finding.

Examine the site's documentation. Verify there is a documented procedure for changing the password for the Account of Last Resort when an individual with knowledge of the password leaves the group. An acceptable practice is to either create a new account and password each time or change the password.

If a procedure for changing the password for the Account of Last Resort when an individual with knowledge of the password leaves the group is not documented or implemented, this is a finding."
  desc 'fix', 'Modify the password for the Account of Last Resort.

1. Using the management console, navigate to "Settings".
2. Select "Users".
3. Click on the local account name representing the Account of Last Resort.
4. In the "Edit User" section, enter and confirm the new password. 
5. Click "Save Settings".

If the Account of Last Resort has been removed after installation and configuration per vendor-recommended best practice (BROM-00-000300), either create a new account and password or change the password.'
  impact 0.5
  ref 'DPMS Target Bromium Secure Platform'
  tag check_id: 'C-80115r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80443'
  tag rid: 'SV-95147r1_rule'
  tag stig_id: 'BROM-00-000690'
  tag gtitle: 'SRG-APP-000317'
  tag fix_id: 'F-87249r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002142']
  tag nist: ['AC-2 (10)']
end
