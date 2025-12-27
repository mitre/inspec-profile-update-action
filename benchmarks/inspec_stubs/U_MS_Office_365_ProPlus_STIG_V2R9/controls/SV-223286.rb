control 'SV-223286' do
  title 'The Office client must be prevented from polling the SharePoint Server for published links.'
  desc 'This policy setting controls whether Office 365 ProPlus applications can poll Office servers to retrieve lists of published links. 

If this policy setting is enabled, Office 365 ProPlus applications cannot poll an Office server for published links. 

If this policy setting is disabled or not configured, users of Office 365 ProPlus applications can see and use links to Microsoft SharePoint Server sites from those applications. Published links can be configured to Office applications during initial deployment, and can add or change links as part of regular operations. These links appear on the My SharePoint Sites tab of the Open, Save, and Save As dialog boxes when opening and saving documents from these applications. Links can be targeted so they only appear to users who are members of particular audiences. 

Note: This policy setting applies to Microsoft SharePoint Server specifically. It does not apply to Microsoft SharePoint Foundation.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2016 >> Server Settings >> Disable the Office client from polling the SharePoint Server for published links is set to "Enabled".

Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\microsoft\\office\\16.0\\common\\portal

If the value for linkpublishingdisabled is REG_DWORD = "1", this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2016 >> Server Settings >> Disable the Office client from polling the SharePoint Server for published links to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-24959r572107_chk'
  tag severity: 'medium'
  tag gid: 'V-223286'
  tag rid: 'SV-223286r879587_rule'
  tag stig_id: 'O365-CO-000003'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24947r572108_fix'
  tag 'documentable'
  tag legacy: ['SV-108749', 'V-99645']
  tag cci: ['CCI-000381', 'CCI-001662']
  tag nist: ['CM-7 a', 'SC-18 (1)']
end
