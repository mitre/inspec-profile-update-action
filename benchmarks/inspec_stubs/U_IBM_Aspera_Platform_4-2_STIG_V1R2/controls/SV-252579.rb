control 'SV-252579' do
  title 'IBM Aspera Faspex must disable account identifiers after 35 days of inactivity.'
  desc 'Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained.'
  desc 'check', 'If the IBM Aspera Faspex feature of the Aspera Platform is not installed, this is Not Applicable.

Verify IBM Aspera Faspex disables account identifiers after 35 days of inactivity: 

- Log in to the IBM Aspera Faspex web page as a user with administrative privilege. 
- Select the "Server" tab.
- Select the "Configuration" tab.
- Select the "Security" section.
- Under the "Faspex accounts" "Remove users" section, verify the following:
- Verify the "Local users" option is checked.
- Verify the "Local users" options is set to "35" days or less.
- Verify the "DS users" option is checked.
- Verify the "DS users" options is set to "35" days or less.
- Verify the "SAML users" option is checked.
- Verify the "SAML users" options is set to "35" days or less.

If the "Local users" options is set to more than "35" days or the option is not checked, this is a finding.

If the "DS users" options is set to more than "35" days or the option is not checked, this is a finding.

If the "SAML users" options is set to more than "35" days or the option is not checked, this is a finding.'
  desc 'fix', 'Configure IBM Aspera Faspex to disable account identifiers after 35 days of inactivity: 

- Log in to the IBM Aspera Faspex web page as a user with administrative privilege. 
- Select the "Server" tab.
- Select the "Configuration" tab.
- Select the "Security" section.
- Under the "Faspex accounts" "Remove users" section, edit the following:
- Put a check in the "Local users" option check box.
- Edit the "Local users" option to "35" days or less.
- Put a check in the "DS users" option check box.
- Edit the "DS users" option to "35" days or less.
- Put a check in the "SAML users" option check box.
- Edit the "SAML users" option to "35" days or less.
- Select "Update" at the bottom of the page.'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56035r817905_chk'
  tag severity: 'medium'
  tag gid: 'V-252579'
  tag rid: 'SV-252579r817907_rule'
  tag stig_id: 'ASP4-FA-050140'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag fix_id: 'F-55985r817906_fix'
  tag 'documentable'
  tag cci: ['CCI-000795']
  tag nist: ['IA-4 e']
end
