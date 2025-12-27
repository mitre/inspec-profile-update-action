control 'SV-33600' do
  title 'Hidden markup options must be visible.'
  desc 'PowerPoint presentations that are saved in standard or HTML format can contain a flag indicating whether markup (comments or ink annotations) in the presentation should be visible when the presentation is open. PowerPoint ignores this flag when opening a file, and always displays any markup present in the file. In addition, when saving a file, PowerPoint sets the flag to display markup when the presentation is next opened.
If this default configuration is changed, PowerPoint sets the flag according to the state of the Show Markup option on the Review tab of the Ribbon when it saves presentations in standard or HTML format. In addition, PowerPoint enables or disables the Show Markup option according to the way the flag is set when it opens files, which means that a presentation saved with hidden markup is opened with the markup still hidden.
If a file is saved with hidden markup, users might inadvertently distribute sensitive comments or information to others via the presentation file.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2010 -> PowerPoint Options -> Security “Make hidden markup visible” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\powerpoint\\options

Criteria: If the value MarkupOpenSave is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2010 -> PowerPoint Options -> Security “Make hidden markup visible” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft PowerPoint 2010'
  tag check_id: 'C-34064r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17752'
  tag rid: 'SV-33600r1_rule'
  tag stig_id: 'DTOO290 -  PowerPoint'
  tag gtitle: 'DTOO290 - Make Hidden marks visible in PowerPoint'
  tag fix_id: 'F-29742r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
