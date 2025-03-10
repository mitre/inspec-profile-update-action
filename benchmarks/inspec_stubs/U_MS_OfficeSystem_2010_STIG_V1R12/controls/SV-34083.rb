control 'SV-34083' do
  title 'Office Live Workspace Integration must be off.'
  desc 'This setting controls the exposing of entry points for Office Live Workspace Integration features.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Office Live Workspace “Turn Off Office Live Workspace Integration” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\common\\officeliveworkspace

Criteria: If the value TurnOffOfficeLiveWorkspaceIntegration is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Office Live Workspace “Turn Off Office Live Workspace Integration” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2010'
  tag check_id: 'C-34222r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26627'
  tag rid: 'SV-34083r1_rule'
  tag stig_id: 'DTOO307 - Office System'
  tag gtitle: 'DTOO307 - Office Live Workspace Integration'
  tag fix_id: 'F-29913r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
