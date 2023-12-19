control 'SV-251214' do
  title 'Redis Enterprise DBMS must be configured in accordance with the security configuration settings based on DoD security configuration and implementation guidance, including STIGs, NSA configuration guides, CTOs, DTMs, and IAVMs.'
  desc 'Configuring the DBMS to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across the DoD that reflects the most restrictive security posture consistent with operational requirements. 

In addition to this STIG, sources of guidance on security and information assurance exist. These include NSA configuration guides, CTOs, DTMs, and IAVMs. The DBMS must be configured in compliance with guidance from all such relevant sources.'
  desc 'check', 'The organization that is implementing Redis Enterprise must review the documentation and configuration to determine if it is configured in accordance with DoD security configuration and implementation guidance, including STIGs, NSA configuration guides, CTOs, DTMs, and IAVMs.

If Redis Enterprise is not configured in accordance with security configuration settings, this is a finding.'
  desc 'fix', 'Follow all DoD security configuration and implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs and IAVMs to configure the Redis Enterprise security configuration settings.'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54649r804830_chk'
  tag severity: 'medium'
  tag gid: 'V-251214'
  tag rid: 'SV-251214r804832_rule'
  tag stig_id: 'RD6X-00-007800'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-54603r804831_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
