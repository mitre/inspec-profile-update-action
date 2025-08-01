control 'SV-89663' do
  title 'The MQ Appliance network device must terminate shared/group account credentials when members leave the group.'
  desc 'A shared/group account credential is a shared form of authentication that allows multiple individuals to access the MQ Appliance network device using a single account. If shared/group account credentials are not terminated when individuals leave the group, the user that left the group can still gain access even though they are no longer authorized. 

The only local account on the MQ Appliance should be the emergency admin account of last resort referred to as the "Fallback user". 

This account is automatically inactive and not accessible as long as LDAP access is enabled. If network access to the LDAP server is lost, the MQ appliance will automatically enable the Fallback user account to allow for emergency administrative access. 

If a former admin knows the Fallback user password, still has network access, and can force the MQ appliance to not communicate with the LDAP server, they could access the MQ appliance using the Fallback user credentials. 

The Fallback user account password must be changed whenever MQ administrators leave the group/team or if their roles change and they no longer require access.'
  desc 'check', 'Log on to the MQ appliance WebGUI as an admin user. Click Administration (gear icon) >> Access. Select User Account and User Group options. 

Review user names that are displayed. 

Local user accounts should not be shared. The only exception is the local "Fallback" user account of last resort, which is used for emergency access. 

Verify that no user accounts other than the designated Fallback user emergency account exist or are shared. 

Verify the local Fallback user password is changed whenever MQ administrators leave the team and no longer have a need to access the MQ device. 

If any user accounts other than the Fallback user exist or are shared, or if the local Fallback user password is not changed when MQ admins leave the team/group, this is a finding.'
  desc 'fix', 'Log on to the MQ appliance WebGUI as an admin user. Click Administration (gear icon) >> Access. Select User Account and User Group options. 

Configure no local accounts other than the Fallback user emergency account. 

Change the local Fallback user account password whenever MQ admin team members leave the group or no longer require access.'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74841r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74989'
  tag rid: 'SV-89663r1_rule'
  tag stig_id: 'MQMH-ND-000910'
  tag gtitle: 'SRG-APP-000317-NDM-000282'
  tag fix_id: 'F-81605r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002142']
  tag nist: ['AC-2 (10)']
end
