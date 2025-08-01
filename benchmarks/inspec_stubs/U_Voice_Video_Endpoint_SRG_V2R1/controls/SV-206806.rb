control 'SV-206806' do
  title 'The Voice Video Endpoint used for unclassified communication within a Sensitive Compartmented Information Facility (SCIF) or Special Access Program Facility (SAPF) must be National Telecommunications Security Working Group (NTSWG)-approved device in accordance with the Committee on National Security Systems Instruction (CNSSI) 5000.'
  desc 'Configuring the Voice Video Endpoint to implement CNSSI 5000 for unclassified communication within SCIFs and SAPF ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Voice Video Endpoints may transmit classified conversations over unclassified networks. Voice Video Endpoint microphones, speakers, and supporting electronics may pick up conversation audio within the area and conduct it over the network connection, even when the endpoint is on-hook, powered or not. The Technical Surveillance Counter-Measures (TSCM) program protects sensitive government information, to include classified information, through the establishment of on-hook audio security standards. Voice Video Endpoints certified by NTSWG are modified to prevent this behavior, or limit it to within acceptable levels.

References:
CNSS Instruction No. 5000, Guidelines for Voice over Internet Protocol (VoIP), dated August 2016
CNSS Instruction No. 5001, Type-Acceptance Program for Voice over Internet Protocol (VoIP) Telephones, dated December 2007
CNSS Instruction No. 5007, Telephone Security Equipment Submission and Evaluation Procedures, dated April 2013
IC Tech Spec-For ICD/ICS 705, Technical Specifications for Construction and Management of Sensitive Compartmented Information Facilities, version 1.3 dated September 10, 2015
Joint Air Force, Army, Navy (JAFAN) 6/0 Manual; Special Access Program Security Manual – Revision 1, dated May 29, 2008
Joint Air Force, Army, Navy (JAFAN) 6/9 Manual; Physical Security Standards for Special Access Program Facilities, dated March 23, 2004'
  desc 'check', 'If the Voice Video Endpoint is not used for unclassified communication within a SCIF or SAPF, this check procedure is Not Applicable.

Verify the Voice Video Endpoint used for unclassified communication within a SCIF or SAPF is an NTSWG-approved device meeting the requirements outlined in CNSSI 5000.

Confirm a valid NTSWG certification seal is affixed to the Voice Video Endpoint with no indication of tampering.

If the Voice Video Endpoint is not an NTSWG-approved device with an affixed certification seal, this is a finding.

If the Voice Video Endpoint reveals any evidence of tampering, or the seal is broken, cut, or in any way tampered with, this is a finding.'
  desc 'fix', 'Replace the Voice Video Endpoint used for unclassified communication within a SCIF or SAPF with an NTSWG-approved device meeting the requirements outlined in CNSSI 5000.

Confirm a valid NTSWG certification seal is affixed to the Voice Video Endpoint with no indication of tampering. The list of NTSWG-approved instruments is available on the National Counterintelligence and Security Center website using the URL below, then clicking on "TSG-6-Approved Telephones (PDF)" link to download the list:

https://www.dni.gov/index.php/ncsc-what-we-do/ncsc-physical-security-mission

The manufacturer places the certification seals prior to shipment, and if the seal is broken, cut, or in any way tampered with, it is no longer considered valid.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7062r459021_chk'
  tag severity: 'medium'
  tag gid: 'V-206806'
  tag rid: 'SV-206806r604140_rule'
  tag stig_id: 'SRG-NET-000512-VVEP-00065'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-7062r459022_fix'
  tag 'documentable'
  tag legacy: ['SV-86295', 'V-71671']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
