control 'SV-30027' do
  title 'Maximum failed password attempts before disable delay must be set to 3 or less.'
  desc 'The Maximum failed attempts before disable delay is not set to 3. This specifies the number of consecutive incorrect password attempts the Hardware Management Console allows as 3 times, before setting a 60-minute delay to attempt to retry the password. The improper setting of any of these fields, individually or in combination with another, can compromise the security of the processing environment. Note: The Hardware Management Console does not allow a revoke of a userID. A 60- minute delay time setting is being substituted.'
  desc 'check', 'Have the System Administrator display the maximum failed attempts on the user properties table on the Hardware Management Console before disable delay is invoked.

Maximum Failed Attempts and Disable Delay are found in User Profiles by selecting the user, selecting modify user and then selecting User Properties. 

If the Maximum failed attempts before disable delay is invoked is set at greater than 3, then this is a FINDING.'
  desc 'fix', 'The System Administrator will display the User Properties window on the Hardware Management Console for each user and verify that the maximum attempts before disable delay is set to 3 or less and will update them if this is not true.

Maximum Failed Attempts and Disable Delay are found in User Profiles by selecting the user, selecting modify user and then selecting User Properties.'
  impact 0.5
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-29862r1_chk'
  tag severity: 'medium'
  tag gid: 'V-24359'
  tag rid: 'SV-30027r2_rule'
  tag stig_id: 'HMC0130'
  tag gtitle: 'HMC0130'
  tag fix_id: 'F-26746r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Systems Programmer']
  tag ia_controls: 'ECLO-1, ECLO-2'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
