control 'SV-225655' do
  title 'The Samsung SDS EMM must automatically disable accounts after a 35 day period of account inactivity (local accounts).'
  desc 'Attackers that are able to exploit an inactive account can potentially obtain and maintain undetected access to an application. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained. Applications need to track periods of user inactivity and disable accounts after 35 days of inactivity. Such a process greatly reduces the risk that accounts will be hijacked, leading to a data compromise. 

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality. 

This policy does not apply to either emergency accounts or infrequently used accounts. Infrequently used accounts are local login administrator accounts used by system administrators when network or normal logon/access is not available. Emergency accounts are administrator accounts created in response to crisis situations.

SFR ID: FMT_SMF.1(2)b. / AC-2(3)

'
  desc 'check', 'Review Samsung SDS EMM server documentation and configuration settings to determine if the admin account is automatically disabled after 35 days. 

On the MDM console, verify that the MDM console Inactivity Limit on Admin Accounts (days) is set to "35". 

If sub-administrators or read-only administrators do not sign in for 35 days, their accounts are locked.

If the MDM console Inactivity Limit on Admin Accounts (days) is not set to "35", this is a finding.'
  desc 'fix', 'Configure the Samsung SDS EMM to disable accounts after 35 days.

On the MDM console, do the following:
1. Log in to the Admin Console using a web browser.
2. Go to Setting >> Server >> Configuration and set Inactivity Limit on Admin Accounts (days) to "35" days.
3. Click the "Save" button.'
  impact 0.5
  ref 'DPMS Target Samsung SDS EMM'
  tag check_id: 'C-27356r560987_chk'
  tag severity: 'medium'
  tag gid: 'V-225655'
  tag rid: 'SV-225655r588007_rule'
  tag stig_id: 'SSDS-00-200240'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-27344r560988_fix'
  tag satisfies: ['SRG-APP-000025', 'PP-MDM-991000']
  tag 'documentable'
  tag cci: ['CCI-000017']
  tag nist: ['AC-2 (3) (d)']
end
