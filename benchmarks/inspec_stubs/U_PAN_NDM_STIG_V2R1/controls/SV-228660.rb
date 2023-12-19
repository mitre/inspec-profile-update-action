control 'SV-228660' do
  title 'The Palo Alto Networks security platform must automatically lock the account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes are exceeded.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.

This should not be configured in Device >> Setup >> Management >> Authentication Settings; instead, an authentication profile should be configured with lockout settings of three failed attempts and a lockout time of zero minutes.  The Lockout Time is the number of minutes that a user is locked out if the number of failed attempts is reached (0-60 minutes, default 0). 0 means that the lockout is in effect until it is manually unlocked.'
  desc 'check', 'Go to Device >> Administrators.
If there is no authentication profile configured for each account (aside from the emergency administration account), this is a finding.

Note which authentication profile is used for each account.
Go to Device >> Authentication Profile.
Check the authentication profile used for each account (noted in the previous step). 
If the Lockout Time is not set to "0" (zero), this is a finding.'
  desc 'fix', %q(This should not be configured in Device >> Setup >> Management >> Authentication Settings; instead, an authentication profile should be configured with lockout settings of three failed attempts and a lockout time of zero minutes.
Go to Device >> Authentication Profile
Select the configured authentication profile, or select "Add" (in the bottom-left corner of the pane) to create a new one.
In the "Authentication Profile" field, enter the name of the authentication profile that will be used to control each person's authentication process.
The "Lockout Time (min)" field is the lockout duration; this must be set to "0".  This will keep the lockout in effect until it is manually unlocked.
In the "Failed Attempts" field, enter "3".
Select "OK".

Apply the authentication profile to the Administrator accounts.
Go to Device >> Administrators
Select each configured account, or select "Add" (in the bottom-left corner of the pane) to create a new one.
In the "Authentication Profile" field, enter the configured authentication profile.
Select "OK".

This authentication profile should not be applied to the emergency administration account since it has special requirements.
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.)
  impact 0.5
  ref 'DPMS Target Palo Alto Networks NDM'
  tag check_id: 'C-30895r513583_chk'
  tag severity: 'medium'
  tag gid: 'V-228660'
  tag rid: 'SV-228660r513585_rule'
  tag stig_id: 'PANW-NM-000092'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-30872r513584_fix'
  tag 'documentable'
  tag legacy: ['SV-77237', 'V-62747']
  tag cci: ['CCI-000366', 'CCI-002238']
  tag nist: ['CM-6 b', 'AC-7 b']
end
