control 'SV-33460' do
  title 'Connection verification of permissions must be enforced.'
  desc "Users are not required to connect to the network to verify permissions. If users do not need their licenses confirmed when attempting to open Office documents, they might be able to access documents after their licenses have been revoked. Also, it is not possible to log the usage of files with restricted permissions if users' licenses are not confirmed."
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Manage Restricted Permissions “Always require users to connect to verify permission” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\common\\drm

Criteria: If the value RequireConnection is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Manage Restricted Permissions “Always require users to connect to verify permission” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2010'
  tag check_id: 'C-33943r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17731'
  tag rid: 'SV-33460r1_rule'
  tag stig_id: 'DTOO201 - Office System'
  tag gtitle: 'DTOO201 - Connection permissions verification'
  tag fix_id: 'F-29632r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
