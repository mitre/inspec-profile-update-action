control 'SV-256846' do
  title 'Compliance Guardian must accept FICAM-approved third-party credentials.'
  desc 'Access may be denied to legitimate users if FICAM-approved third-party credentials are not accepted. 

This requirement typically applies to organizational information systems that are accessible to nonfederal government agencies and other partners. This allows federal government-relying parties to trust such credentials at their approved assurance levels.

Third-party credentials are those credentials issued by nonfederal government entities approved by the Federal Identity, Credential, and Access Management (FICAM) Trust Framework Solutions initiative.'
  desc 'check', 'Note: This requirement is Not Applicable if ADFS is not being utilized.

ADFS can be used to federate with approved third-party users.

Check the Compliance Guardian configuration option for ADFS Integration.
- Log on to Compliance Guardian with admin account.
- On the Control Panel page in the General Security section, click "Authentication Manager". 
- Verify that the ADFS Integration option is enabled.

If the ADFS Integration is not enabled, this is a finding.'
  desc 'fix', 'Configure Compliance Guardian to use ADFS Integration.
- Log on to Compliance Guardian with admin account.
- On the Control Panel page in the General Security section, click "Authentication Manager".
- Click "ADFS Integration" to open ADFS Integration Configuration Wizard page and complete the configuration.
- Click "Enable link" of the ADFS Integration row to enable ADFS Integration.
- Back on the Control Panel page in the Account section, click "Users". 
- Navigate to "Add User" page.
- Select ADFS Claim from the drop-down list in the "User Type" field.
- Select the Claim Name and input the Claim Value in the "How Would You Like To Retrieve User Information" field.
- Save the settings.'
  impact 0.5
  ref 'DPMS Target AvePoint Compliance Guardian'
  tag check_id: 'C-60521r890146_chk'
  tag severity: 'medium'
  tag gid: 'V-256846'
  tag rid: 'SV-256846r890148_rule'
  tag stig_id: 'APCG-00-000035'
  tag gtitle: 'SRG-APP-000404'
  tag fix_id: 'F-60464r890147_fix'
  tag 'documentable'
  tag cci: ['CCI-002011']
  tag nist: ['IA-8 (2)']
end
