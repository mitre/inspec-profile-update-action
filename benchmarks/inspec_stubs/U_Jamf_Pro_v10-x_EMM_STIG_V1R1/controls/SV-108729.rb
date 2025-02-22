control 'SV-108729' do
  title 'The Jamf Pro EMM must automatically disable accounts after a 35 day period of account inactivity (local accounts).'
  desc 'Attackers that are able to exploit an inactive account can potentially obtain and maintain undetected access to an application. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained. Applications need to track periods of user inactivity and disable accounts after 35 days of inactivity. Such a process greatly reduces the risk that accounts will be hijacked, leading to a data compromise. 

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality. 

This policy does not apply to either emergency accounts or infrequently used accounts. Infrequently used accounts are local login administrator accounts used by system administrators when network or normal logon/access is not available. Emergency accounts are administrator accounts created in response to crisis situations.

SFR ID: FMT_SMF.1(2)b. / AC-2(3)

'
  desc 'check', 'Interview the site Jamf Pro EMM system administrator. Confirm a script is used to periodically check when each local account was last accessed by the user and disable the account if there is a 35-day or more period of account inactivity.

If a script is not used to periodically check when each local account was last accessed by the user and disable the account or if there is a 35-day or more period of account inactivity, this is a finding.'
  desc 'fix', 'Note: There is no setting on the Jamf Pro EMM console to implement this requirement. 

A script should be used to periodically check when each local account was last accessed by the user and disable the account if there is a 35-day or more period of account inactivity. The script should be developed by the site or provided by Jamf.'
  impact 0.5
  ref 'DPMS Target JAMF v10.x EMM'
  tag check_id: 'C-98475r1_chk'
  tag severity: 'medium'
  tag gid: 'V-99625'
  tag rid: 'SV-108729r1_rule'
  tag stig_id: 'JAMF-10-100800'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-105309r1_fix'
  tag satisfies: ['SRG-APP-000025']
  tag 'documentable'
  tag cci: ['CCI-000017']
  tag nist: ['AC-2 (3) (d)']
end
