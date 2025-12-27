control 'SV-228555' do
  title 'Office must be configured to not allow read with browsers.'
  desc 'The Windows Rights Management Add-on for Internet Explorer provides a way for users who do not use the 2013 Office release to view, but not alter, files with restricted permissions. By default, IRM-enabled files are saved in a format that cannot be viewed by using the Windows Rights Management Add-on. If this setting is enabled, an embedded rights-managed HTML version of the content is saved with each IRM-enabled file, which can be viewed in Internet Explorer using the add-on, representing the risk of documents being read by those without the rights and not intended to have access to the document.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Manage Restricted Permissions "Allow users with earlier versions of Office to read with browsers" is set to "Disabled". 

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\common\drm

If the value 'IncludeHTML' is REG_DWORD = 0, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Manage Restricted Permissions "Allow users with earlier versions of Office to read with browsers" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30788r498943_chk'
  tag severity: 'medium'
  tag gid: 'V-228555'
  tag rid: 'SV-228555r508020_rule'
  tag stig_id: 'DTOO200'
  tag gtitle: 'SRG-APP-000328'
  tag fix_id: 'F-30773r498944_fix'
  tag 'documentable'
  tag legacy: ['V-17583', 'SV-52749']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
