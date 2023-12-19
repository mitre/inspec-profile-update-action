control 'SV-228451' do
  title 'Trusted add-ins behavior for email must be configured.'
  desc "This policy setting can be used to specify a list of trusted add-ins that can be run without being restricted by the security measures in Outlook. If you enable this policy setting, a list of trusted add-ins and hashes is made available that you can modify by adding and removing entries. The list is empty by default. To create a new entry, enter a DLL file name in the 'Value Name' column and the hash result in the 'Value' column. If you disable or do not configure this policy setting, the list of trusted add-ins is empty and unused, so the recommended EC and SSLF settings do not create any usability issues. However, users who rely on add-ins that access the Outlook object model might be repeatedly prompted unless administrators enable this setting and add the add-ins to the list.Note - You can also configure Exchange Security Form settings by enabling the 'Outlook Security Mode' setting in User Configuration\\Administrative Templates\\Microsoft Outlook 2016\\Security\\Security Form Settings\\Microsoft Outlook 2016 Security and selecting 'Use Outlook Security Group Policy' from the drop-down list."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Security Form Settings -> Programmatic Security -> Trusted Add-ins "Configure trusted add-ins" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\Outlook\\security

Criteria: If the value trustedaddins does not exist, this is not a finding. If the value trustedaddins exists, but with no entries, this is not a finding.
If the value trustedaddins exists, with entries, this is a finding.

In some reported configurations, the value remains after disabling the setting but the value is empty.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Security Form Settings -> Programmatic Security -> Trusted Add-ins "Configure trusted add-ins" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30684r497675_chk'
  tag severity: 'medium'
  tag gid: 'V-228451'
  tag rid: 'SV-228451r508021_rule'
  tag stig_id: 'DTOO256'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-30669r497676_fix'
  tag 'documentable'
  tag legacy: ['SV-85817', 'V-71193']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
