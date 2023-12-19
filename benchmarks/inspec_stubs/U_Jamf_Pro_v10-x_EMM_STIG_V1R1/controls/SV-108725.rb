control 'SV-108725' do
  title 'The Jamf Pro EMM local accounts must be configured with password maximum lifetime of 3 months.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed at specific intervals. 

One method of minimizing this risk is to use complex passwords and periodically change them. If the application does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the system and/or application passwords could be compromised. 

This requirement does not include emergency administration accounts which are meant for access to the application in case of failure. These accounts are not required to have maximum password lifetime restrictions.

SFR ID: FMT_SMF.1(2)b. / IA-5 (1) (d)

'
  desc 'check', %q(To verify the "password maximum lifetime" of "3" months for the local account's password is set, do the following:

1. Open the Jamf Pro EMM console.
2. Click "Settings".
3. Click "System Settings".
4. Click "Jamf Pro System User Accounts & Groups".
5. Click "Password Policy".
6. Verify "password maximum lifetime" of "3" months.

If the "password maximum lifetime" for local account's password is not set to "3" months, this is a finding.)
  desc 'fix', %q(To configure the "password maximum lifetime" of "3" months for the local account's password, do the following:

1. Open the Jamf Pro EMM console.
2. Click "Settings".
3. Click "System Settings".
4. Click "Jamf Pro System User Accounts & Groups".
5. Click "Password Policy".
6. Click "Edit".
7. Set the "password maximum lifetime" of "3" months.)
  impact 0.5
  ref 'DPMS Target JAMF v10.x EMM'
  tag check_id: 'C-98471r1_chk'
  tag severity: 'medium'
  tag gid: 'V-99621'
  tag rid: 'SV-108725r1_rule'
  tag stig_id: 'JAMF-10-100770'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-105305r1_fix'
  tag satisfies: ['SRG-APP-000174']
  tag 'documentable'
  tag cci: ['CCI-000174']
  tag nist: ['AU-12 (1)']
end
