control 'SV-206860' do
  title 'The Voice Video Session Manager used for unclassified communication within a Sensitive Compartmented Information Facility (SCIF) or Special Access Program Facility (SAPF) must be configured in accordance with the Committee on National Security Systems Instruction (CNSSI) 5000.'
  desc 'Configuring the Voice Video Session Manager in accordance with CNSSI 5000 for unclassified communication systems supporting VVoIP endpoints within SCIFs and SAPFs ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements. 

Voice Video Session Managers may support voice video endpoints that could potentially be activated from the session manager (inadvertently or covertly) and transmit classified conversations over unclassified networks if not properly configured. Voice Video Endpoint microphones and speakers may be activated to pick up conversation audio within the area and conduct it over the network connection, even when the endpoint is on-hook. The Technical Surveillance Counter-Measures (TSCM) program protects sensitive government information, to include classified information, through the establishment of on-hook audio security standards. 

References:
CNSS Instruction No. 5000, Guidelines for Voice over Internet Protocol (VoIP), dated September 2016
IC Tech Spec-For ICD/ICS 705, Technical Specifications for Construction and Management of Sensitive Compartmented Information Facilities, version 1.3 dated September 10, 2015
Joint Air Force, Army, Navy (JAFAN) 6/0 Manual; Special Access Program Security Manual – Revision 1, dated May 29, 2008
Joint Air Force, Army, Navy (JAFAN) 6/9 Manual; Physical Security Standards for Special Access Program Facilities, dated March 23, 2004'
  desc 'check', 'If the Voice Video Session Manager does not support voice video endpoints used for unclassified communication within a SCIF or SAPFs, this check procedure is Not Applicable.

Verify the Voice Video Session Manager supporting voice video endpoints used for unclassified communication within a SCIF or SAPF is configured in accordance with the CNSSI 5000.

If the Voice Video Session Manager is not configured in accordance with the CNSSI 5000, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager supporting voice video endpoints used for unclassified communication within a SCIF or SAPF to be configured in accordance with CNSSI 5000.'
  impact 0.5
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7115r459030_chk'
  tag severity: 'medium'
  tag gid: 'V-206860'
  tag rid: 'SV-206860r508661_rule'
  tag stig_id: 'SRG-NET-000512-VVSM-00057'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-7115r459031_fix'
  tag 'documentable'
  tag legacy: ['V-71689', 'SV-86313']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
