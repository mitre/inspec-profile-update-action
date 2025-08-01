control 'SV-33433' do
  title 'Database functionality configurations must be displayed to the user.'
  desc 'When users open an untrusted Access 2010 database that contains user-programmed executable components, Access opens the database with the components disabled and displays the Message Bar with a warning that database content has been disabled. Users can inspect the contents of the database, but cannot use any disabled functionality until they enable it by clicking Options on the Message Bar and selecting the appropriate action.
The default configuration can be changed so that users see a dialog box when they open an untrusted database with executable components. Users must then choose whether to enable or disable the components before working with the database. In these circumstances users frequently enable the components, even if they do not require them. Executable components can be used to launch an attack against a computer environment.
Disabling this setting enforces Access 2010 to display the action items, so is unlikely to cause usability issues.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Access 2010 -> Tools \\ Security “Modal Trust Decision Only” must be “Disabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\access\\security

Criteria: If the value ModalTrustDecisionOnly is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Access 2010 -> Tools \\ Security “Modal Trust Decision Only” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Access 2010'
  tag check_id: 'C-33916r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17757'
  tag rid: 'SV-33433r1_rule'
  tag stig_id: 'DTOO135 - Access'
  tag gtitle: 'DTOO135 - Modal Trust Decision Only'
  tag fix_id: 'F-29605r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
