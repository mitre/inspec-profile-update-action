control 'SV-256847' do
  title 'Compliance Guardian must conform to FICAM-issued profiles.'
  desc 'Without conforming to FICAM-issued profiles, the information system may not be interoperable with FICAM-authentication protocols, such as SAML 2.0 and OpenID 2.0.

This requirement addresses open identity management standards.'
  desc 'check', 'Note:  This requirement is Not Applicable is ADFS is not being utilized.

Check the Compliance Guardian configuration option for ADFS Integration.
- Log on to Compliance Guardian with admin account.
- On the Control Panel page in the General Security section, click "Authentication Manager". 
- Verify that the ADFS Integration option is enabled.

If the ADFS Integration is not enabled, this is a finding.'
  desc 'fix', 'Configure Compliance Guardian to use ADFS Integration.
- Log on to Compliance Guardian with admin account.
- On the Control Panel page in the General Security section, click "Authentication Manager".
- Click "ADFS Integration" to open ADFS Integration Configuration Wizard page and complete the configuration.
- Click "Enable" link of the "ADFS Integration" row to enable ADFS Integration.
- Back to the Control Panel page in the Account section, click "Users". 
- Navigate to "Add User" page.
- Select "ADFS Claim" from the drop-down list in the "User Type" field.
- Select the Claim Name and input the Claim Value in the "How Would You Like To Retrieve User Information" field.
- Save the settings.'
  impact 0.5
  ref 'DPMS Target AvePoint Compliance Guardian'
  tag check_id: 'C-60522r890149_chk'
  tag severity: 'medium'
  tag gid: 'V-256847'
  tag rid: 'SV-256847r890151_rule'
  tag stig_id: 'APCG-00-000040'
  tag gtitle: 'SRG-APP-000405'
  tag fix_id: 'F-60465r890150_fix'
  tag 'documentable'
  tag cci: ['CCI-002014']
  tag nist: ['IA-8 (4)']
end
