control 'SV-96145' do
  title 'XenDesktop StoreFront must accept Personal Identity Verification (PIV) credentials.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.

DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under HSPD 12, as well as a primary component of layered protection for national security systems.

'
  desc 'check', 'Open the Citrix StoreFront management console.

Select the "Store" node in the left pane.

In the "Actions" pane, click "Manage Authentication Methods".

Select only the "Smart Card" method.

If the "Smart Card" method is not selected or if other methods are selected, this is a finding.

Note: If a NetScaler Gateway is handling authentication, "Pass-through from NetScaler Gateway" may also be selected, this is not a finding.'
  desc 'fix', 'From the Citrix StoreFront management console >> Store node >> Actions pane >> Manage Authentication Methods, select only the "Smart Card" method.'
  impact 0.5
  ref 'DPMS Target XenDesktop 7.x StoreFront'
  tag check_id: 'C-81171r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81431'
  tag rid: 'SV-96145r1_rule'
  tag stig_id: 'CXEN-SF-000855'
  tag gtitle: 'SRG-APP-000391'
  tag fix_id: 'F-88249r1_fix'
  tag satisfies: ['SRG-APP-000391', 'SRG-APP-000033', 'SRG-APP-000392', 'SRG-APP-000439', 'SRG-APP-000440', 'SRG-APP-000442']
  tag 'documentable'
  tag cci: ['CCI-000213', 'CCI-001953', 'CCI-001954', 'CCI-002418', 'CCI-002421', 'CCI-002422']
  tag nist: ['AC-3', 'IA-2 (12)', 'IA-2 (12)', 'SC-8', 'SC-8 (1)', 'SC-8 (2)']
end
