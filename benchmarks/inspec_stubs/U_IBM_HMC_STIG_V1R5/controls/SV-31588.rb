control 'SV-31588' do
  title 'A maximum of 60-minute delay must be specified for the password retry after 3 failed attempts to enter your password'
  desc 'The Maximum failed attempts before disable delay is not set to 3. This specifies the number of consecutive incorrect password attempts the Hardware Management Console allows as 3 times, before setting a 60-minute delay to attempt to retry the password. The improper setting of any of these fields, individually or in combination with another, can compromise the security of the processing environment. Note: The Hardware Management Console does not allow a revoke of a user ID.A 60-minute delay time setting is being substituted.'
  desc 'check', 'Have the System Administrator display the Disable delay in minutes.

Disable Delay is found in User Profiles by selecting the user, selecting modify user and then selecting User Properties. 

If this is les than 60 minutes then this is a finding.

Note:       Hardware Management Console does not have the ability to revoke a user ID, so a 60-minute delay has been imposed instead.'
  desc 'fix', 'The System Administrator will display the User Properties window on the Hardware Management Console for each user and verify that the disable delay is set to 60 or more.   

Maximum Failed Attempts and Disable Delay are found in User Profiles by selecting the user, selecting modify user and then selecting User Properties.'
  impact 0.3
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-31864r1_chk'
  tag severity: 'low'
  tag gid: 'V-25404'
  tag rid: 'SV-31588r2_rule'
  tag stig_id: 'HMC0135'
  tag gtitle: 'HMC0135'
  tag fix_id: 'F-28357r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Systems Programmer']
  tag ia_controls: 'ECLO-1, ECLO-2'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
