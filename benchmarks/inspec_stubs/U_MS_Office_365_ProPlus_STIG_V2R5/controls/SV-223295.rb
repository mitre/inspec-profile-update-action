control 'SV-223295' do
  title 'The load of controls in Forms3 must be blocked.'
  desc %q(This policy setting allows the user to control how ActiveX controls in UserForms should be initialized based upon whether they are Safe for Initialization (SFI) or Unsafe for Initialization (UFI). 
 
ActiveX controls are Component Object Model (COM) objects and have unrestricted access to users' computers. ActiveX controls can access the local file system and change the registry settings of the operating system. If a malicious user repurposes an ActiveX control to take over a user's computer, the effect could be significant. To help improve security, ActiveX developers can mark controls as SFI, which means that the developer states that the controls are safe to open and run and not capable of causing harm to any computers. If a control is not marked SFI, the control could adversely affect a computer, or the developers may not have tested the control in all situations and are not sure whether their control might be compromised at some future date. SFI controls run in safe mode, which limits their access to the computer. For example, a worksheet control can both read and write files when it is in unsafe mode, but perhaps only read from files when it is in safe mode. This functionality allows the control to be used in very powerful ways when safety was not important, but the control would still be safe for use in a Web page. If a control is not marked as SFI, it is marked UFI, which means that it is capable of affecting a user's computer. If UFI ActiveX controls are loaded, they are always loaded in unsafe mode. 
 
If this policy setting is enabled, choose from four options for loading controls in UserForms: 
 
1. For a UFI or SFI signed control that supports safe and unsafe mode, load the control in unsafe mode. For an SFI signed control that only supports a safe mode configuration, load the control in safe mode. This option enforces the default configuration. 
 
2. Users are prompted to determine how UserForm forms will load. The prompt only displays once per session within an application. When users respond to the prompt, loading continues based on whether the control is UFI or SFI: 
 
- For a UFI signed control, if users respond "Yes" to the prompt, load the control in unsafe mode. If users respond "No", load the control using the default properties. 
- For an SFI signed control that supports both safe and unsafe modes, if users respond "Yes" to the prompt, load the control in unsafe mode. If users respond "No", load the control using safe mode. If the SFI control can only support safe mode, load the control in safe mode. This option is the default configuration in the Microsoft Office 365 ProPlus release. 
 
3. Users are prompted to determine how UserForm forms will load. The prompt only displays once per session within an application. When users respond to the prompt, loading continues based on whether the control is UFI or SFI: 
 
- For a UFI signed control, if users respond "Yes" to the prompt, load the control in unsafe mode. If users respond "No", load the control with its default properties. 
- For an SFI signed control, load in safe mode. 
 
4. For a UFI signed control, load with the default properties of the control. For an SFI signed control, load in safe mode (considered to be the safest mode). 
 
If  this policy setting is disabled or not configured, the behavior is as if this policy setting is enabled and then select option "1".)
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2016 >> Security Settings "Load Controls in Forms3" is set to Enabled and 1 from drop down. (For a UFI or SFI signed control that supports safe and unsafe mode, load the control in unsafe mode. For an SFI signed control that only supports a safe mode configuration, load the control in safe mode. This option enforces the default configuration.)".

Use the Windows Registry Editor to navigate to the following key:

HKCU\\Software\\Policies\\Microsoft\\VBA\\Security

If the value LoadControlsInForms is REG_DWORD=1, this is not a finding.

If the value LoadControlsInForms does not exist, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2016 >> Security Settings "Load Controls in Forms3" to "Enabled:1" or set it to "Disabled."'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-24968r811476_chk'
  tag severity: 'medium'
  tag gid: 'V-223295'
  tag rid: 'SV-223295r822336_rule'
  tag stig_id: 'O365-CO-000013'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-24956r822335_fix'
  tag 'documentable'
  tag legacy: ['SV-108769', 'V-99665']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
