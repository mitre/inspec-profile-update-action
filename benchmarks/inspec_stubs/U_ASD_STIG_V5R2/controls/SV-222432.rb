control 'SV-222432' do
  title 'The application must enforce the limit of three consecutive invalid logon attempts by a user during a 15 minute time period.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced.

Limits are imposed by locking the account.

User notification when three failed logon attempts are exceeded is an operational consideration determined by the application owner. In some instances the operational situation may dictate that no notice is to be provided to the user when their account is locked. In other situations, the user may be notified their account is now locked. This decision is left to the application owner based upon their operational scenarios.'
  desc 'check', 'All testing must be performed within a 15-minute window.

Log on to the application with a test user account.

Intentionally enter an incorrect user password or pin.

Repeat 2 times within 15 minutes for a total of three failed attempts.

Notification of a locked account may or may not be provided.

Using the correct user password or pin, attempt to logon a 4th time.

If the logon is successful upon the 4th attempt the account was not locked after the third failed attempt and this is a finding.'
  desc 'fix', 'Configure the application to enforce an account lock after 3 failed logon attempts occurring within a 15-minute window.'
  impact 0.7
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24102r493204_chk'
  tag severity: 'high'
  tag gid: 'V-222432'
  tag rid: 'SV-222432r508029_rule'
  tag stig_id: 'APSC-DV-000530'
  tag gtitle: 'SRG-APP-000065'
  tag fix_id: 'F-24091r493205_fix'
  tag 'documentable'
  tag legacy: ['V-69343', 'SV-83965']
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
