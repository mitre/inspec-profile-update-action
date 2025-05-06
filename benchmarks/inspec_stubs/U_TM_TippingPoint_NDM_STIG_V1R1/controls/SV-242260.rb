control 'SV-242260' do
  title 'The password for the local account of last resort and the device password (if configured) must be changed when members who had access to the password leave the role and are no longer authorized access.'
  desc 'If shared/group account credentials are not terminated when individuals leave the group, the user that left the group can still gain access even though they are no longer authorized. There may also be instances when specific user actions need to be performed on the network device without unique administrator identification or authentication. 

A shared/group account credential is a shared form of authentication that allows multiple individuals to access the network device using a single account.'
  desc 'check', 'Have the local representative show password change logs or documentation to show this is a local process.

If the password for the local account of last resort is not changed when members who had access to the password leave the role and are no longer authorized access, this is a finding.'
  desc 'fix', 'Change the password for the account of last resort.

1. Navigate to Admin >> Authentication and Authorization >> Users.
2. Select the account of last resort.
3. Click Edit and Select Authentication.
4. Enter and confirm the password.

To change the password for managed devices, if configured: 
Navigate to Devices >> All Devices >> Member Summary >> Device Users.

The Device User Accounts screen displays a table that lists the user accounts available on managed devices.'
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint NDM'
  tag check_id: 'C-45535r710785_chk'
  tag severity: 'medium'
  tag gid: 'V-242260'
  tag rid: 'SV-242260r710787_rule'
  tag stig_id: 'TIPP-NM-000950'
  tag gtitle: 'SRG-APP-000317-NDM-000282'
  tag fix_id: 'F-45493r710786_fix'
  tag 'documentable'
  tag cci: ['CCI-002142']
  tag nist: ['AC-2 (10)']
end
