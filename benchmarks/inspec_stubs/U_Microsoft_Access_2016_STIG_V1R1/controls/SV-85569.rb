control 'SV-85569' do
  title 'Database functionality configurations must be displayed to the user.'
  desc 'This policy setting controls how Access notifies users about untrusted components. If you enable this policy setting, when users attempt to open an untrusted Access database that contains user-programmed executable components, users see a dialog box where they then must choose whether to enable or disable the components before they can work with the database. If you disable or do not configure this policy setting, when users open an untrusted Access database that contains user-programmed executable components, Access opens the database with the components disabled and displays the Message Bar with a warning that database content has been disabled. Users can inspect the contents of the database, but cannot use any disabled functionality until they enable it by clicking Options on the Message Bar and selecting the appropriate action.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Access 2016 -> Tools \\ Security "Modal Trust Decision Only" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\access\\security

Criteria: If the value ModalTrustDecisionOnly is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Access 2016 -> Tools \\ Security "Modal Trust Decision Only" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Access 2016'
  tag check_id: 'C-71373r2_chk'
  tag severity: 'medium'
  tag gid: 'V-70945'
  tag rid: 'SV-85569r1_rule'
  tag stig_id: 'DTOO135'
  tag gtitle: 'SRG-APP-000488'
  tag fix_id: 'F-77277r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002460']
  tag nist: ['SC-18 (4)']
end
