control 'SV-238035' do
  title 'Connection verification of permissions must be enforced.'
  desc 'This policy setting controls whether users are required to connect to the Internet or a local network to have their licenses confirmed every time they attempt to open Excel workbooks, InfoPath forms or templates, Outlook e-mail messages, PowerPoint presentations, or Word documents that are protected by Information Rights Management (IRM).  This policy is useful if you want to log the usage of files with restricted permissions on the server. If you enable this policy setting, users are required to connect to verify permissions.  This policy setting will only affect protected files created on machines where the policy is enabled. If you disable or do not configure this policy setting, users are not required to connect to the network to verify permissions.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Manage Restricted Permissions "Always require users to connect to verify permission" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\common\\drm

Criteria: If the value RequireConnection is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Manage Restricted Permissions "Always require users to connect to verify permission" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2016'
  tag check_id: 'C-41245r650670_chk'
  tag severity: 'medium'
  tag gid: 'V-238035'
  tag rid: 'SV-238035r650672_rule'
  tag stig_id: 'DTOO201'
  tag gtitle: 'SRG-APP-000340'
  tag fix_id: 'F-41204r650671_fix'
  tag 'documentable'
  tag legacy: ['SV-85505', 'V-70881']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
