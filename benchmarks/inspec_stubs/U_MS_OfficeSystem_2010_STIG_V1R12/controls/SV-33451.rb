control 'SV-33451' do
  title 'Automatic receiving of small updates to improve reliability must be disallowed.'
  desc 'Office Diagnostics is used to improve the user experience by periodically downloading a small file to the computer with updated help information about specific problems. If Office Diagnostics is enabled, it collects information about specific errors and the IP address of the computer. When new help information is available, that help information is downloaded to the computer that experienced the related problems. Office Diagnostics does not transmit any personally identifiable information to Microsoft other than the IP address of the computer requesting the update. 
By default, users have the opportunity to opt into receiving updates from Office Diagnostics the first time they run a 2010 Office application. If your organization has policies that govern the use of external resources such as Office Diagnostics, allowing users to opt in to this feature might cause them to violate these policies.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010-> Privacy -> Trust Center “Automatically receive small updates to improve reliability” must be set to “Disabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key:

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\common

Criteria: If the value UpdateReliabilityData is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010-> Privacy -> Trust Center “Automatically receive small updates to improve reliability” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2010'
  tag check_id: 'C-33934r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17740'
  tag rid: 'SV-33451r1_rule'
  tag stig_id: 'DTOO185 - Office System'
  tag gtitle: 'DTOO185 - Do not receive Automatic small updates'
  tag fix_id: 'F-29623r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
