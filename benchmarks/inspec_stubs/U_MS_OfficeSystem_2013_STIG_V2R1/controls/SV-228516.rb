control 'SV-228516' do
  title 'Office client polling of SharePoint servers published links must be disabled.'
  desc 'Users of Office applications can see and use links to Microsoft Office SharePoint Server sites from those applications. Administrators configure published links to Office applications during initial deployment, and can add or change links as part of regular operations. These links appear on the My SharePoint Sites tab of the Open, Save, and Save As dialog boxes when opening and saving documents from these applications. Links can be targeted so that they only appear to users who are members of particular audiences.
If a malicious person gains access to the list of published links, they could modify the links to point to unapproved sites, which could make sensitive data vulnerable to exposure.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Server Settings "Disable the Office client from polling the SharePoint Server for published links" is set to "Enabled".

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\common\portal

If the value 'LinkPublishingDisabled' is REG_DWORD = 1, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Server Settings "Disable the Office client from polling the SharePoint Server for published links" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30749r498826_chk'
  tag severity: 'medium'
  tag gid: 'V-228516'
  tag rid: 'SV-228516r508020_rule'
  tag stig_id: 'DTOO208'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-30734r498827_fix'
  tag 'documentable'
  tag legacy: ['SV-52755', 'V-17670']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
