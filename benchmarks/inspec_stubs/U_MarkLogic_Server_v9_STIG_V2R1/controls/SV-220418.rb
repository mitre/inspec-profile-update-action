control 'SV-220418' do
  title 'MarkLogic Server must be configured in accordance with the security configuration settings based on DoD security configuration and implementation guidance, including STIGs, NSA configuration guides, CTOs, DTMs, and IAVMs.'
  desc 'Configuring the DBMS to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements. 

In addition to this SRG, sources of guidance on security and information assurance exist. These include NSA configuration guides, CTOs, DTMs, and IAVMs. The DBMS must be configured in compliance with guidance from all such relevant sources.'
  desc 'check', 'Determine the applicable DoD security configuration and implementation guidance for the deployment environment. Asses the MarkLogic Server documentation and configuration in accordance with the applicable guidance.

If MarkLogic is not configured in accordance with security configuration settings, this is a finding.'
  desc 'fix', 'From the list of applicable DoD security configuration and implementation guidance, address the items that the MarkLogic Server configuration does not meet.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22133r401705_chk'
  tag severity: 'medium'
  tag gid: 'V-220418'
  tag rid: 'SV-220418r622777_rule'
  tag stig_id: 'ML09-00-012400'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-22122r401706_fix'
  tag 'documentable'
  tag legacy: ['SV-110183', 'V-101079']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
