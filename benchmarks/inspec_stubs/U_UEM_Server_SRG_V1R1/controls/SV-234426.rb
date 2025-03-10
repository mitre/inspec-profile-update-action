control 'SV-234426' do
  title 'The UEM server must, when a component failure is detected, activate an organization-defined alarm and/or automatically shut down the application or the component.'
  desc 'Predictable failure prevention requires organizational planning to address system failure issues. If components key to maintaining systems security fail to function, the system could continue operating in an insecure state. The organization must be prepared and the application must support requirements that specify if the application must alarm for such conditions and/or automatically shut down the application or the system. 

This can include conducting a graceful application shutdown to avoid losing information. Automatic or manual transfer of components from standby to active mode can occur, for example, upon detection of component failures. 

Satisfies:FAU_ALT_EXT.1.1, FAU_GEN.1.1(1), FMT_SMF.1.1(2)c.8 
Reference:PP-MDM-411065, PP-MDM-412000'
  desc 'check', 'Verify the UEM server, when a component failure is detected, activates an organization-defined alarm and/or automatically shuts down the application or the component.

If the UEM server, when a component failure is detected, does not activate an organization-defined alarm and/or automatically shut down the application or the component, this is a finding.'
  desc 'fix', 'Configure the UEM server to activate an organization-defined alarm and/or automatically shut down the application or the component when a component failure is detected.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37611r614288_chk'
  tag severity: 'medium'
  tag gid: 'V-234426'
  tag rid: 'SV-234426r617355_rule'
  tag stig_id: 'SRG-APP-000268-UEM-000153'
  tag gtitle: 'SRG-APP-000268'
  tag fix_id: 'F-37576r614289_fix'
  tag 'documentable'
  tag cci: ['CCI-001328']
  tag nist: ['SI-13 (4) (b)']
end
