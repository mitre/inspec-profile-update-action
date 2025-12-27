control 'SV-245772' do
  title 'Information Assurance - COOP Plan and Testing (Not in Place for Information Technology Systems or Not Considered in the organizational Holistic Risk Assessment)'
  desc 'Failure to develop a COOP and test it periodically can result in the partial or total loss of operations and INFOSEC. A contingency plan is necessary to reduce mission impact in the event of system compromise or disaster.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, Paragraphs 15 & 32

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
CP-2, CP-2(1) through CP-2(8), CP-4, CP-4(1) through CP-4(4), CP-6, CP-7, CP-9, MA-6

DoDI 8500.01, SUBJECT: Cybersecurity, March 14, 2014 , Enclosure 3, paragraph 3.

DoDD 3020.26, SUBJECT: Department of Defense Continuity Programs, January 9, 2009

DoDI 3020.42,  SUBJECT: Defense Continuity Plan Development, February 17, 2006

Implementation of DoD Continuity Strategy - Deputy Secretary of Defense, 25 May 07

National Security Presidential Directive (NSPD) 51 / Homeland Security Presidential Directive (HSPD) 20 - National Continuity Policy, 9 May 07

Federal Continuity Directives 1 Oct 12 and 2 Jul 13, Federal Executive Branch National Continuity Program and Requirements.

NIST Special Publication 800-34 Rev. 1, Contingency Planning Guide for Federal Information Systems, May 2010

DoD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 8, paragraph 8-101.g. and 8-302.c.'
  desc 'check', 'Check there is a written COOP plan for inspected information technology systems:    

1. If a COOP or Disaster Recovery Plan is not in place, ensure the AO has considered and accepted the risk (specifically for lack of COOP) from a Holistic Risk Assessment of the organization.   

2. Check COOP documentation to ensure the plan is tested at least annually.  Also check for discrepancies noted during the tests and if corrective action has been taken. 

3. Conduct a cursory review of the COOP to ensure it is commensurate for COOP of IT systems as detailed within the risk assessment concerning recovery times and testing requirement(s). 

NOTES: 

1. Certain large computing centers like the DISA Computing Services (DECCs) may offer COOP as a fee for service option. Since this is applicable to "customer" applications it should not be a finding attributed to the DECC. If appropriate, COOP or lack thereof if cited as a finding in this instance should be attributed to the specific customer.  

2. This requirement should not be applied to a tactical environment, unless it is a fixed computer facility supporting operations within a Theater of Operations.  The standards to be applied for applicability in a tactical environment are:  1) The facility containing the computer room has been in operation over 1-year. 2) The facility is "fixed facility" - a hard building made from normal construction materials - wood, steel, brick, stone, mortar, etc.'
  desc 'fix', 'Continuity of Operations Plans (COOP) must be developed and tested for ALL DoDIN connected systems to ensure system and data availability in the event of any type of failure.  If no COOP is in place ensure the risk has been (specifically for lack of a COOP) accepted by the responsible Authorizing Official (AO) in a Holistic Risk Assessment of the organization.'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49203r769976_chk'
  tag severity: 'medium'
  tag gid: 'V-245772'
  tag rid: 'SV-245772r822832_rule'
  tag stig_id: 'IA-02.02.01'
  tag gtitle: 'IA-02.02.01'
  tag fix_id: 'F-49158r769977_fix'
  tag 'documentable'
  tag legacy: ['V-30997', 'SV-41043r3_rule']
end
