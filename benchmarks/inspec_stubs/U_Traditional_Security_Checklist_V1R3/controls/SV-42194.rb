control 'SV-42194' do
  title 'Vault/Secure Room Storage Standards - Automated Entry Control System (AECS) Transmission Line Security:  
AECS Transmission lines traversing an uncontrolled area (not within at least a Secret Controlled Access Area (CAA) ) shall use line supervision OR Electrical, mechanical, or electromechanical access control devices, which do not constitute an AECS that are used to control access during duty hours must have all electrical components,  that traverse outside minimally a Secret Controlled Access Area (CAA), secured within conduit.'
  desc 'Persons not vetted to at least the same level of classification residing on the information systems being protected by the AECS or other access control system components could gain access to the unprotected transmission line and tamper with it to facilitate surreptitious access to the secure space.  Proper line supervision and/or physical protection within conduit will enable detection of line tampering.  Such failure to meet standards for line supervision and physical protection could result in the loss or compromise of classified material.

REFERENCES:

The Information Security Oversight Office (ISOO): http://www.archives.gov/isoo/   Implementing Directive for Protection of Classified (for Executive Order 13526), 32 CFR Parts 2001 and 2003 Classified National Security Information: paragraph 2001.43 Storage, (2) Secret.

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: PE-3, PE-4, and PE-6.

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information:  Appendix to Enclosure 3, paragraphs 3.a.(5)(d) and 3.c.(4).

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 5, Section 3, paragraph 5-313. g. and h.'
  desc 'check', '1. Where Automated Entry Control Systems (AECS)protect SIPRNet assets in Secure Rooms, Vaults, or secret/TS CAAs: Ensure  that transmission lines used to carry access authorizations, personal identification data, or verification data between devices or equipment, which are located outside "minimally" a Secret Controlled Access Area (CAA) have line supervision.

2. Electrical, mechanical, or electromechanical access control devices, which do not constitute an AECS that are used to control access during duty hours (while under direct continuous visual observation and control of a cleared employee or via CCTV) must have all electrical components, including wiring, or mechanical links (cables, rods, and so on) accessible only from inside the area, or, if they traverse outside a controlled area "minimally" a Secret Controlled Access Area (CAA), they must be physically secured within conduit to preclude surreptitious manipulation of components.
                                       
TACTICAL ENVIRONMENT:  This check is applicable where Vaults/Secure Rooms are used to protect classified materials or systems in a tactical environment. The only exception will be for urgent (short term) tactical operations or other contingency situations where fixed facilities and equipment are not yet present or incapable of being used.'
  desc 'fix', '1. Where Automated Entry Control Systems (AECS)protect SIPRNet assets in Secure Rooms, Vaults, or secret/TS CAAs: Ensure  that transmission lines used to carry access authorizations, personal identification data, or verification data between devices or equipment, which are located outside "minimally" a Secret Controlled Access Area (CAA) have line supervision.  

2. Where electrical, mechanical, or electromechanical access control devices, which do not constitute an AECS are used to control access during duty hours (while under direct continuous visual observation and control of a cleared employee or via CCTV) they must have all electrical components, including wiring, or mechanical links (cables, rods, and so on) accessible only from inside the area, or, if they traverse outside a controlled area "minimally" a Secret Controlled Access Area (CAA), they must be physically secured within conduit to preclude surreptitious manipulation of components.'
  impact 0.5
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-40606r9_chk'
  tag severity: 'medium'
  tag gid: 'V-31897'
  tag rid: 'SV-42194r3_rule'
  tag stig_id: 'IS-02.02.09'
  tag gtitle: 'Vault/Secure Room Storage Standards - Automated Entry Control System Transmission Line Security'
  tag fix_id: 'F-35835r7_fix'
  tag 'documentable'
end
