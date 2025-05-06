control 'SV-222401' do
  title 'The application must ensure each unique asserting party provides unique assertion ID references for each SAML assertion.'
  desc '<0> [object Object]'
  desc 'check', 'Ask the application representative for the design document.

Review the design document for web services using SAML assertions.

If the application does not utilize SAML assertions, this check is not applicable.

Review the design document and verify SAML assertion identifiers are not reused by a single asserting party.

If the design document does not exist, or does not indicate SAML assertion identifiers which are unique for each asserting party, this is a finding.'
  desc 'fix', 'Design and configure each SAML assertion authority to use unique assertion identifiers.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24071r493111_chk'
  tag severity: 'medium'
  tag gid: 'V-222401'
  tag rid: 'SV-222401r508029_rule'
  tag stig_id: 'APSC-DV-000210'
  tag gtitle: 'SRG-APP-000014'
  tag fix_id: 'F-24060r493112_fix'
  tag legacy: ['V-69283', 'SV-83905']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
