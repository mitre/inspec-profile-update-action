control 'SV-33462' do
  title 'Changing permissions on rights managed content for users must be enforced.'
  desc 'This setting controls whether Office 2010 users can change permissions for content that is protected with Information Rights Management (IRM).   The Information Rights Management feature of Office 2010 allows individuals and administrators to specify access permissions to Word documents, Excel workbooks, PowerPoint presentations, InfoPath templates and forms, and Outlook e-mail messages. This functionality helps prevent sensitive information from being printed, forwarded, or copied by unauthorized people.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Manage Restricted Permissions “Prevent users from changing permissions on rights managed content” must be set to “Disabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\common\\drm

Criteria: If the value DisableCreation is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Manage Restricted Permissions “Prevent users from changing permissions on rights managed content” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2010'
  tag check_id: 'C-33945r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17765'
  tag rid: 'SV-33462r1_rule'
  tag stig_id: 'DTOO199 - Office System'
  tag gtitle: 'DTOO199 - Permissions on managed content'
  tag fix_id: 'F-29634r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
