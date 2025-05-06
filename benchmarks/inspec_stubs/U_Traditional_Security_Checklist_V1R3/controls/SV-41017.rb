control 'SV-41017' do
  title 'Protected Distribution System (PDS) Documentation - Signed Approval'
  desc 'A PDS that is not approved could cause an Information System Security Manager (ISSM), Authorizing Official (AO) and other concerned managerial personnel to not be fully aware of all vulnerabilities and residual risk of IA systems under their purview.

REFERENCES:   
                              
CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 35.c.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016 Chapter 5, Section 4, paragraphs 5-402.c. and 5-403  

DoD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DoD Information Security Program: Protection of Classified Information, Encl 4, para 3.b. and 4.a.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls:  PE-4, SC-7, and SC-8

CNSSI No. 7003, September 2015, Protected Distribution Systems (PDS), Section I, paragraph 1., Section III, paragraph 5., Section 4, paragraph 11., Section V, paragraph 14., Section VIII, paragraphs 23.c. and 27.a., Section X, paragraphs 30.a & b., Section XI, paragraph 34.b.2) and Annex A.'
  desc 'check', 'Validate that: 

1. The approval authority is the system Authorizing Official (AO), cognizant security office for contractors or other Department or Agency designee having Approval Authority for the installation and operation of the PDS and
 
2. A documented approval of the PDS is signed and dated by the current approval authority.
 
NOTE: In tactical environments mobile systems employing inter-shelter cabling need not be re-approved for each relocation if the relocation provides security comparable to that of the original approval. Otherwise, new approval must be obtained.'
  desc 'fix', '1. The approval authority must be the system Authorizing Official (AO), cognizant security office for contractors or other Department or Agency designee having Approval Authority for the for the installation and operation of the PDS and 

2. A documented approval of the PDS must be signed and dated by the current approval authority.
 
NOTE: In tactical environments mobile systems employing inter-shelter cabling need not be re-approved for each relocation if the relocation provides security comparable to that of the original approval. Otherwise, new approval must be obtained.'
  impact 0.3
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-39637r7_chk'
  tag severity: 'low'
  tag gid: 'V-30974'
  tag rid: 'SV-41017r3_rule'
  tag stig_id: 'CS-05.03.01'
  tag gtitle: 'PDS Documentation - Signed Approval'
  tag fix_id: 'F-34784r6_fix'
  tag 'documentable'
end
