control 'SV-222552' do
  title 'The application must map the authenticated identity to the individual user or group account for PKI-based authentication.'
  desc 'Without mapping the certificate used to authenticate to a corresponding user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.

Some CAs will include identifying information like an email address within the certificate itself. When the email is assigned to an individual, this helps to identify the individual user who has been assigned the certificate. When identifying information is not available within the certificate itself, the application must provide a mapping that allows administrators to quickly determine who the owner of the certificate is. When responding to a security incident, particularly involving user access violations, time is of the essence so this information must be readily available to investigators.'
  desc 'check', 'Review the application documentation and interview the application administrator to identify how the application maps individual user certificates or group accounts to individual users.

Access the application as a regular user while reviewing the application logs to determine if the application records the individual name of the user or if the application only includes certificate information.

If the application only logs certificate information which contains no discernable user data, ask the system admin what their process is for mapping the certificate information to the user.

If the application does not map the certificate data to an individual user or group, or if the administrator has no automated process established for determining the identity of the user, this is a finding.'
  desc 'fix', 'Configure the application to map certificate information to individual users or group accounts or create a process for automatically determining the individual user or group based on certificate information provided in the logs.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24222r493564_chk'
  tag severity: 'medium'
  tag gid: 'V-222552'
  tag rid: 'SV-222552r879614_rule'
  tag stig_id: 'APSC-DV-001830'
  tag gtitle: 'SRG-APP-000177'
  tag fix_id: 'F-24211r493565_fix'
  tag 'documentable'
  tag legacy: ['V-70153', 'SV-84775']
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
