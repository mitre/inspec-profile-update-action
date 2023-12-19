control 'SV-234252' do
  title 'Citrix StoreFront server must accept Personal Identity Verification (PIV) credentials.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.

DoD has mandated the use of the Common Access Card (CAC) to support identity management and personal authentication for systems covered under HSPD 12, as well as a primary component of layered protection for national security systems.

'
  desc 'check', 'Open the Citrix StoreFront management console and select the "Store" node in the left pane.
For each Store listed, select the store and perform the following:
1) From the Actions menu item, click "Manage Authentication Methods".
2) Ensure only "Smart card" is selected. If using remote access "Pass-through from NetScaler Gateway" may also be selected.

If the "Smart Card" method is not selected, or if other methods are selected, this is a finding.
If "Pass-through from NetScaler Gateway" is selected, this is not a finding.'
  desc 'fix', 'Open the Citrix StoreFront management console and select the "Store" node in the left pane.
For each Store listed, select the store and perform the following:
1) From the Actions menu item, click "Manage Authentication Methods".
2) Check "Smart card" and uncheck any other authentication methods. If using remote access, select "Pass-through from NetScaler Gateway".'
  impact 0.5
  ref 'DPMS Target Citrix VAD 7.x StoreFront'
  tag check_id: 'C-37437r612116_chk'
  tag severity: 'medium'
  tag gid: 'V-234252'
  tag rid: 'SV-234252r628797_rule'
  tag stig_id: 'CVAD-SF-000855'
  tag gtitle: 'SRG-APP-000391'
  tag fix_id: 'F-37402r612117_fix'
  tag satisfies: ['SRG-APP-000391', 'SRG-APP-000033', 'SRG-APP-000392', 'SRG-APP-000439', 'SRG-APP-000440', 'SRG-APP-000442']
  tag 'documentable'
  tag cci: ['CCI-000213', 'CCI-001953', 'CCI-001954', 'CCI-002418', 'CCI-002421', 'CCI-002422']
  tag nist: ['AC-3', 'IA-2 (12)', 'IA-2 (12)', 'SC-8', 'SC-8 (1)', 'SC-8 (2)']
end
