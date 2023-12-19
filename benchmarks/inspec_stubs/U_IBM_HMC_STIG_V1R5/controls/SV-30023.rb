control 'SV-30023' do
  title 'Individual user accounts with passwords must be maintained for the Hardware Management Console operating system and application.'
  desc 'Without identification and authentication, unauthorized users could reconfigure the Hardware Management Console or disrupt its operation by logging in to the  system or application and execute unauthorized commands. The System Administrator will ensure individual user accounts with passwords are set up and maintained for the Hardware Management Console.'
  desc 'check', 'Have the System Administrator prove that individual USER IDs are specified for each user and DD2875 are on file for each user. 

If USERIDs are shared among multiple users and crresponding DD2875 forms do not exist for each user, then this is a FINDING.'
  desc 'fix', 'Have the System Administrator verify that all users of the Hardware Management Console are individually defined with USER IDs  and passwords and that their roles and responsibilities are documented. Verify that a DD2875 exists for each USER ID.'
  impact 0.5
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-29861r1_chk'
  tag severity: 'medium'
  tag gid: 'V-24355'
  tag rid: 'SV-30023r2_rule'
  tag stig_id: 'HMC0100'
  tag gtitle: 'HMC0100'
  tag fix_id: 'F-26745r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Systems Programmer']
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000760']
  tag nist: ['IA-1 a 2']
end
