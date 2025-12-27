control 'SV-234533' do
  title 'The UEM server must require end-point devices to reauthenticate when organization-defined circumstances or situations requiring reauthentication.'
  desc 'This requirement refers to the end-point device user reauthenticating to the device.  The following are examples of organization-defined circumstances or situations requiring reauthentication: 

(i) After a screen lock; 
(ii) After device reboot; 
(iii) Before installation of new device policy or profile;
(iv) Before executing a device reset or wipe. 

Satisfies:FMT_SMF.1.1(2) b 
Reference:PP-MDM-431016'
  desc 'check', 'Verify the UEM server requires end-point devices to reauthenticate when organization-defined circumstances or situations requiring reauthentication.

If the UEM server does not require end-point devices to reauthenticate when organization-defined circumstances or situations requiring reauthentication, this is a finding.'
  desc 'fix', 'Configure the UEM server to require end-point devices to reauthenticate when organization-defined circumstances or situations requiring reauthentication.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37718r615981_chk'
  tag severity: 'medium'
  tag gid: 'V-234533'
  tag rid: 'SV-234533r617355_rule'
  tag stig_id: 'SRG-APP-000390-UEM-000261'
  tag gtitle: 'SRG-APP-000390'
  tag fix_id: 'F-37683r615243_fix'
  tag 'documentable'
  tag cci: ['CCI-002039']
  tag nist: ['IA-11']
end
