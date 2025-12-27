control 'SV-222408' do
  title 'Shared/group account credentials must be terminated when members leave the group.'
  desc 'If shared/group account credentials are not terminated when individuals leave the group, the user that left the group can still gain access even though they are no longer authorized. A shared/group account credential is a shared form of authentication that allows multiple individuals to access the application using a single account. There may also be instances when specific user actions need to be performed on the information system without unique user identification or authentication. Examples of credentials include passwords and group membership certificates.'
  desc 'check', 'Review the application documentation and determine if there is a requirement for shared or group accounts.

If there is no official requirement for shared or group application accounts, this requirement is not applicable.

Interview the application representative and identify shared/group accounts.

Have the application representative provide their procedures for account management as it pertains to group users.

Validate there is a procedure for deleting either member accounts or the entire group account when member leave the group.

If there is no process for handling group account credentials, this is a finding.'
  desc 'fix', 'Create a procedure for deleting either member accounts or the entire group account when members leave the group.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24078r493132_chk'
  tag severity: 'medium'
  tag gid: 'V-222408'
  tag rid: 'SV-222408r879694_rule'
  tag stig_id: 'APSC-DV-000290'
  tag gtitle: 'SRG-APP-000317'
  tag fix_id: 'F-24067r493133_fix'
  tag 'documentable'
  tag legacy: ['SV-83919', 'V-69297']
  tag cci: ['CCI-002142']
  tag nist: ['AC-2 (10)']
end
