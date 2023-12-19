control 'SV-228554' do
  title 'Changing permissions on rights managed content for users must be enforced.'
  desc 'This setting controls whether Office 2013 users can change permissions for content that is protected with Information Rights Management (IRM). The Information Rights Management feature of Office 2013 allows individuals and administrators to specify access permissions to Word documents, Excel workbooks, PowerPoint presentations, InfoPath templates and forms, and Outlook email messages. This functionality helps prevent sensitive information from being printed, forwarded, or copied by unauthorized people.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Manage Restricted Permissions "Prevent users from changing permissions on rights managed content" is set to "Disabled".

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\common\drm

Criteria: If the value 'DisableCreation' is REG_DWORD = 0, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Manage Restricted Permissions "Prevent users from changing permissions on rights managed content" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30787r557516_chk'
  tag severity: 'medium'
  tag gid: 'V-228554'
  tag rid: 'SV-228554r557517_rule'
  tag stig_id: 'DTOO199'
  tag gtitle: 'SRG-APP-000328'
  tag fix_id: 'F-30772r498941_fix'
  tag 'documentable'
  tag legacy: ['V-17765', 'SV-52748']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
