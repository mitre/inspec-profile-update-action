control 'SV-96643' do
  title 'MongoDB must be configured in accordance with the security configuration settings based on DoD security configuration and implementation guidance, including STIGs, NSA configuration guides, CTOs, DTMs, and IAVMs.'
  desc 'Configuring MongoDB to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

In addition to this SRG, sources of guidance on security and information assurance exist. These include NSA configuration guides, CTOs, DTMs, and IAVMs. MongoDB must be configured in compliance with guidance from all such relevant sources.'
  desc 'check', 'Review the MongoDB documentation and configuration to determine it is configured in accordance with DoD security configuration and implementation guidance, including STIGs, NSA configuration guides, CTOs, DTMs, and IAVMs.

If the MongoDB is not configured in accordance with security configuration settings, this is a finding.'
  desc 'fix', 'Configure MongoDB in accordance with security configuration settings by reviewing the Operation System and MongoDB documentation and applying the necessary configuration parameters to meet the configurations required by the STIG, NSA configuration guidelines, CTOs, DTMs, and IAVMs.'
  impact 0.5
  ref 'DPMS Target MongoDB 3.x'
  tag check_id: 'C-81721r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81929'
  tag rid: 'SV-96643r1_rule'
  tag stig_id: 'MD3X-00-001100'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-88779r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
