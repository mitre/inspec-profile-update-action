control 'SV-222545' do
  title 'The application must enforce a 60-day maximum password lifetime restriction.'
  desc 'Use of passwords for application authentication is intended only for limited situations and should not be used as a replacement for two-factor CAC-enabled authentication.

Examples of situations where a user ID and password might be used include but are not limited to:

- When the application user base does not have a CAC and is not a current DoD employee, member of the military, or a DoD contractor.

- When an application user has been officially designated as a Temporary Exception User; one who is temporarily unable to present a CAC for some reason (lost, damaged, not yet issued, broken card reader) and to satisfy urgent organizational needs must be temporarily permitted to use user ID/password authentication until the problem with CAC use has been remedied.

and

- When the application is publicly available and or hosting publicly releasable data requiring some degree of need-to-know protection.

Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed at specific intervals.

One method of minimizing this risk is to use complex passwords and periodically change them. If the application does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the system and/or application passwords could be compromised.

This requirement does not include emergency administration accounts which are meant for access to the application in case of failure. These accounts are not required to have maximum password lifetime restrictions.'
  desc 'check', 'Review the application documentation and interview the application administrator to identify if the application uses passwords for user authentication.

If the application does not use passwords, the requirement is not applicable.

Access the application management interface and view the user password settings page.

Review user password settings and validate the application is configured to expire and force a password change after 60 days.

If user passwords are not configured to expire after 60 days, or if the application does not have the ability to control this setting, this is a finding.'
  desc 'fix', 'Configure the application to have a maximum password lifetime of 60 days.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24215r493543_chk'
  tag severity: 'medium'
  tag gid: 'V-222545'
  tag rid: 'SV-222545r879611_rule'
  tag stig_id: 'APSC-DV-001770'
  tag gtitle: 'SRG-APP-000174'
  tag fix_id: 'F-24204r493544_fix'
  tag 'documentable'
  tag legacy: ['SV-84195', 'V-69573']
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
