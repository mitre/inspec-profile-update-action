control 'SV-238030' do
  title 'ActiveX control initialization must be disabled.'
  desc 'This policy setting specifies the Microsoft ActiveX« initialization security level for all Microsoft Office applications. ActiveX controls can adversely affect a computer directly. In addition, malicious code can be used to compromise an ActiveX control and attack a computer. To indicate the safety of an ActiveX control, developers can denote them as Safe For Initialization (SFI). SFI indicates that a control is safe to open and run, and that it is not capable of causing a problem for any computer, regardless of whether it has persisted data values or not. If a control is not marked SFI, it is possible that the control could adversely affect a computer--or it could mean that the developers did not test the control in all situations and are not sure whether it might be compromised in the future.   If you enable this policy setting, you can set the ActiveX security level to a number between 1 and 6. These security levels are as follows:   1 - Regardless of how the control is marked, load it and use the persisted values (if any). This setting does not prompt the user.   2 - If SFI, load the control in safe mode and use persisted values (if any). If not SFI, load in unsafe mode with persisted values (if any), or use the default (first-time initialization) settings. This level is similar to the default configuration, but does not prompt the user.   3 - If SFI, load the control in unsafe mode and use persisted values (if any). If not SFI, prompt the user and advise them that it is marked unsafe. If the user chooses No at the prompt, do not load the control. Otherwise, load it with default (first-time initialization) settings.   4 - If SFI, load the control in safe mode and use persisted values (if any). If not SFI, prompt the user and advise them that it is marked unsafe. If the user chooses No at the prompt, do not load the control. Otherwise, load it with default (first-time initialization) settings.   5 - If SFI, load the control in unsafe mode and use persisted values (if any). If not SFI, prompt the user and advise them that it is marked unsafe. If the user chooses No at the prompt, do not load the control. Otherwise, load it with persisted values.    6 - If SFI, load the control in safe mode and use persisted values (if any). If not SFI, prompt the user and advise them that it is marked unsafe. If the user chooses No at the prompt, do not load the control. Otherwise, load it with persisted values.   If you disable or do not configure this policy setting, if a control is marked SFI, the application loads the control in safe mode and uses persisted values (if any). If the control is not marked SFI, the application loads the control in unsafe mode with persisted values (if any), or uses the default (first-time initialization) settings. In both situations, the Message Bar informs users that the controls have been disabled and prompts them to respond.   Important - Some ActiveX controls do not respect the safe mode registry setting, and therefore might load persisted data even though you configure this setting to instruct the control to use safe mode. This setting only increases security for ActiveX controls that are accurately marked as SFI. In situations that involve malicious or poorly designed code, an ActiveX control might be inaccurately marked as SFI.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Security Settings "ActiveX Control Initialization" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\Common\\Security

Criteria: If the value UFIControls exists, this is a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Security Settings "ActiveX Control Initialization" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2016'
  tag check_id: 'C-41240r650655_chk'
  tag severity: 'medium'
  tag gid: 'V-238030'
  tag rid: 'SV-238030r650657_rule'
  tag stig_id: 'DTOO191'
  tag gtitle: 'SRG-APP-000488'
  tag fix_id: 'F-41199r650656_fix'
  tag 'documentable'
  tag legacy: ['SV-85493', 'V-70869']
  tag cci: ['CCI-002460']
  tag nist: ['SC-18 (4)']
end
