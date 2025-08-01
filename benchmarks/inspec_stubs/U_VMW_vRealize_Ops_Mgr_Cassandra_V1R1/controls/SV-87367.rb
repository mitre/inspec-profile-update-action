control 'SV-87367' do
  title 'The DBMS must be configured in accordance with the security configuration settings based on DoD security configuration and implementation guidance, including STIGs, NSA configuration guides, CTOs, DTMs, and IAVMs.'
  desc 'Configuring the DBMS to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements. 

In addition to this SRG, sources of guidance on security and information assurance exist. These include NSA configuration guides, CTOs, DTMs, and IAVMs. The DBMS must be configured in compliance with guidance from all such relevant sources.'
  desc 'check', "Review the Cassandra documentation and configuration to determine if the server is configured in accordance with DoD security configuration and implementation guidance, including STIGs, NSA configuration guides, CTOs, DTMs, and IAVMs.

Obtain supporting documentation from the ISSO.

Verify that this Security Technical Implementation Guide (STIG) is the most current STIG available for Cassandra on vROps. Assess all of the organization's vROps installations to ensure that they are fully compliant with the most current Cassandra STIG.

If the Cassandra configuration is not compliant with the most current Cassandra STIG, this is a finding."
  desc 'fix', 'Configure the Cassandra server in accordance with DoD security configuration and implementation guidance, including STIGs, NSA configuration guides, CTOs, DTMs, and IAVMs.'
  impact 0.3
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72891r1_chk'
  tag severity: 'low'
  tag gid: 'V-72735'
  tag rid: 'SV-87367r1_rule'
  tag stig_id: 'VROM-CS-001075'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-79137r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
