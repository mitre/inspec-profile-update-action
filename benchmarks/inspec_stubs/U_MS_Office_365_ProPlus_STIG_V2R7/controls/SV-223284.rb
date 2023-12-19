control 'SV-223284' do
  title 'The Macro Runtime Scan Scope must be enabled for all documents.'
  desc %q(This policy setting specifies for which documents the VBA Runtime Scan feature is enabled.

If the feature is disabled for all documents, no runtime scanning of enabled macros will be performed.

If the feature is enabled for low trust documents, the feature will be enabled for all documents for which macros are enabled except:
 - Documents opened while macro security settings are set to "Enable All Macros"
 - Documents opened from a Trusted Location
 - Documents that are Trusted Documents
 - Documents that contain VBA that is digitally signed by a Trusted Publisher

If the feature is enabled for all documents, then the above class of documents are not excluded from the behavior.

This protocol allows the VBA runtime to report to the Anti-Virus system certain high-risk code behaviors it is about to execute and allows the Anti-Virus to report back to the process if the sequence of observed behaviors indicates likely malicious activity so the Office application can take appropriate action.

When this feature is enabled, affected VBA projects' runtime performance may be reduced.)
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2016>> Security Settings "Macro Runtime Scan Scope" is set to "Enable for all documents".

Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\microsoft\\office\\16.0\\common\\security

If the value for macroruntimescanscope is REG_DWORD = 2, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2016>> Security Settings "Macro Runtime Scan Scope" to "Enable for all documents".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-24957r572109_chk'
  tag severity: 'medium'
  tag gid: 'V-223284'
  tag rid: 'SV-223284r508192_rule'
  tag stig_id: 'O365-CO-000001'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-24945r442072_fix'
  tag 'documentable'
  tag legacy: ['SV-108745', 'V-99641']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
