control 'SV-245773' do
  title 'Information Assurance - COOP Plan or  Testing (Incomplete)'
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

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 8, paragraph 8-101.g. and 8-302.c.'
  desc 'check', 'This check is for when a reviewer finds that a COOP process is well established within the inspected organization, but it does not include a minority of systems, requirements, or testing of all systems, for which the risk of having no COOP or testing was not accepted by the Authorizing official (AO) in a holistic risk assessment for the organization.

NOTES:  

1. This finding/VUL is only applicable when some of the site/organization systems are connected to the DoDIN and do not have a COOP and/or the COOP is not tested and the risk for not having a COOP and/or documented testing is not accepted by the AO in a holistic risk assessment document.  

2. If this finding/VUL is used, IA-02.02.01 is NA.  

3. This VUL is applicable in a tactical environment if it involves a fixed facility as previously described.'
  desc 'fix', 'ALL systems connected to the DoDIN must be included in the enclave COOP documentation and testing. If it is determined that some (a portion of the systems on site) of the site/organization systems connected to the DoDIN do not need to be included in the COOP (plan and/or testing) then the risk for this must specifically be accepted by the AO in a holistic risk assessment document.'
  impact 0.3
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49204r770297_chk'
  tag severity: 'low'
  tag gid: 'V-245773'
  tag rid: 'SV-245773r770298_rule'
  tag stig_id: 'IA-02.03.01'
  tag gtitle: 'IA-02.03.01'
  tag fix_id: 'F-49159r769980_fix'
  tag 'documentable'
  tag legacy: ['SV-41051r3_rule', 'V-31004']
end
