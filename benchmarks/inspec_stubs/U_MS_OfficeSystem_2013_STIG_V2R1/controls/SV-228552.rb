control 'SV-228552' do
  title 'Load controls in forms3 must be disabled from loading.'
  desc "ActiveX controls are Component Object Model (COM) objects and have unrestricted access to users' computers. ActiveX controls can access the local file system and change the registry settings of the operating system. If a malicious user repurposes an ActiveX control to take over a user's computer, the effect could be significant.
To help improve security, ActiveX developers can mark controls as Safe For Initialization (SFI), which means that the developer states that the controls are safe to open and run and not capable of causing harm to any computers. If a control is not marked SFI, the control could adversely affect a computer--or it could mean the developers did not test the control in all situations and are not sure whether their control might be compromised at some future date.
SFI controls run in safe mode, which limits their access to the computer. For example, a worksheet control can both read and write files when it is in unsafe mode, but perhaps only read from files when it is in safe mode. This functionality allows the control to be used in very powerful ways when safety is not important, but the control would still be safe for use in a Web page.
If a control is not marked as SFI, it is marked Unsafe For Initialization (UFI), which means that it is capable of affecting a user's computer. If UFI ActiveX controls are loaded, they are always loaded in unsafe mode."
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Security Settings "Load Controls in Forms3" is set to "Disabled".

Use the Windows Registry Editor to navigate to the following HKCU\keycupoliciesmsvbasecurity 

If the value 'LoadControlsInForms' exists, this is a finding.)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Security Settings "Load Controls in Forms3" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30785r498934_chk'
  tag severity: 'medium'
  tag gid: 'V-228552'
  tag rid: 'SV-228552r508020_rule'
  tag stig_id: 'DTOO192'
  tag gtitle: 'SRG-APP-000209'
  tag fix_id: 'F-30770r498935_fix'
  tag 'documentable'
  tag legacy: ['SV-52729', 'V-17750']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
