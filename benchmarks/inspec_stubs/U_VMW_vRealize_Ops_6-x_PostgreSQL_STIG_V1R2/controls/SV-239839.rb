control 'SV-239839' do
  title 'The vROps PostgreSQL DB must be configured in accordance with the security configuration settings based on DoD security configuration and implementation guidance, including STIGs, NSA configuration guides, CTOs, DTMs, and IAVMs.'
  desc 'Configuring the DBMS to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements. 

In addition to this SRG, sources of guidance on security and information assurance exist. These include NSA configuration guides, CTOs, DTMs, and IAVMs. The DBMS must be configured in compliance with guidance from all such relevant sources.'
  desc 'check', "Obtain supporting documentation from the ISSO.

Verify that this Security Technical Implementation Guide (STIG) is the most current STIG available for PostgreSQL on vROps. Assess all of the organization's vROps installations to ensure that they are fully compliant with the most current PostgreSQL STIG.

If the PostgreSQL configuration is not compliant with the most current PostgreSQL STIG, this is a finding."
  desc 'fix', 'Install the latest approved security-relevant software updates and document in the supporting documentation.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-43072r663910_chk'
  tag severity: 'medium'
  tag gid: 'V-239839'
  tag rid: 'SV-239839r879887_rule'
  tag stig_id: 'VROM-PG-000625'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-43031r663893_fix'
  tag 'documentable'
  tag legacy: ['SV-99001', 'V-88351']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
