control 'SV-33459' do
  title 'Office must be configured to not allow read with browsers.'
  desc 'The Windows Rights Management Add-on for Internet Explorer provides a way for users who do not use the 2010 Office release to view, but not alter, files with restricted permissions. By default, IRM-enabled files are saved in a format that cannot be viewed by using the Windows Rights Management Add-on. If this setting is enabled, an embedded rights-managed HTML version of the content is saved with each IRM-enabled file, which can be viewed in Internet Explorer using the add-on. This configuration increases the size of rights-managed files, in some cases significantly.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Manage Restricted Permissions “Allow users with earlier versions of Office to read with browsers” must be set to “Disabled”. 

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\common\\drm

Criteria: If the value IncludeHTML is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Manage Restricted Permissions “Allow users with earlier versions of Office to read with browsers” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2010'
  tag check_id: 'C-33942r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17583'
  tag rid: 'SV-33459r1_rule'
  tag stig_id: 'DTOO200 - Office System'
  tag gtitle: 'DTOO200 - Allow users to read with browsers'
  tag fix_id: 'F-29631r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
