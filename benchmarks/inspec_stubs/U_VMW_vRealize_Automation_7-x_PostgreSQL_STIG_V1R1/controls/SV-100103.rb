control 'SV-100103' do
  title 'vRA PostgreSQL must have the latest approved security-relevant software updates installed.'
  desc 'Configuring the DBMS to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements. 

In addition to this SRG, sources of guidance on security and information assurance exist. These include NSA configuration guides, CTOs, DTMs, and IAVMs. The DBMS must be configured in compliance with guidance from all such relevant sources.'
  desc 'check', "Obtain supporting documentation from the ISSO.

Verify that this Security Technical Implementation Guide (STIG) is the most current STIG available for PostgreSQL on vRA  Assess all of the organization's vRA installations to ensure that they are fully compliant with the most current PostgreSQL STIG.

If the PostgreSQL configuration is not compliant with the most current PostgreSQL STIG, this is a finding."
  desc 'fix', 'Install the latest approved security-relevant software updates.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x PostgreSQL'
  tag check_id: 'C-89145r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89453'
  tag rid: 'SV-100103r1_rule'
  tag stig_id: 'VRAU-PG-000490'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-96195r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
