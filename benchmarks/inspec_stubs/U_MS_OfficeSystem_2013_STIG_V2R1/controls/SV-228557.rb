control 'SV-228557' do
  title 'ActiveX control initialization must be disabled.'
  desc 'ActiveX controls can adversely affect a computer directly. In addition, malicious code can be used to compromise an ActiveX control and attack a computer. To indicate the safety of an ActiveX control, developers can denote them as Safe For Initialization (SFI). SFI indicates a control is safe to open and run, and it is not capable of causing a problem for any computer, regardless of whether it has persisted data values or not. 
If a control is not marked SFI, it is possible the control could adversely affect a computer—or it could mean the developers did not test the control in all situations and are not sure whether it might be compromised in the future.
By default, if a control is marked SFI, the application loads the control in safe mode and uses persisted values (if any). If the control is not marked SFI, the application loads the control in unsafe mode with persisted values (if any), or uses the default (first-time initialization) settings. In both situations, the Message Bar informs users the controls have been disabled and prompts them to respond.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Security Settings "ActiveX Control Initialization" is set to "Disabled".
Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\Common\Security

If the value 'UFIControls' exists, this is a finding.)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Security Settings "ActiveX Control Initialization" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30790r498949_chk'
  tag severity: 'medium'
  tag gid: 'V-228557'
  tag rid: 'SV-228557r508020_rule'
  tag stig_id: 'DTOO191'
  tag gtitle: 'SRG-APP-000488'
  tag fix_id: 'F-30775r498950_fix'
  tag 'documentable'
  tag legacy: ['SV-52728', 'V-17547']
  tag cci: ['CCI-002460']
  tag nist: ['SC-18 (4)']
end
