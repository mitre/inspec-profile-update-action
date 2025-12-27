control 'SV-245739' do
  title 'Protected Distribution System (PDS) Documentation - Request for Approval Documentation'
  desc 'A PDS that is not approved could cause an Information System Security Manager (ISSM), Authorizing Official (AO) and other concerned managerial personnel to not be fully aware of all vulnerabilities and residual risk of IA systems under their purview.

REFERENCES:  
                               
CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 35.c.

DoD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016 Chapter 5, Section 4, paragraphs 5-402.c. and 5-403   

DoD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DoD Information Security Program: Protection of Classified Information, Encl 4, para 3.b. and 4.a.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls:  PE-4, SC-7, and SC-8

CNSSI No. 7003, September 2015, Protected Distribution Systems (PDS), Section I, paragraph 1., Section V, paragraph 14., Section VIII, paragraphs 23.c., Section X, paragraphs 30.a., and Annex A.'
  desc 'check', 'This check concerns the documentation prepared and submitted to the PDS approval authority.  Any subsequent requests for modification of the PDS should also be available for review.  Check to ensure:
 
1. The PDS documentation is complete and current. Review a copy of the initial Request for Approval of PDS, which must contain the information IAW Annex A, CNSSI 7003.
  
2. Any requests for modification of the PDS approval are also available for review and contain the appropriate information.

3. PDS are recertified when modified or when the threat level or security posture changes.
 
4. PDS approval documentation and all updates are kept for the lifetime of the physical structure of the PDS.

5. That a standard operating procedure (SOP) to ensure proper installation, maintenance, operation and inspection of the PDS is developed by the PDS owner, approved by the AO, and approved by the cognizant security authority. *The SOP must be submitted as a part of the PDS approval documentation.

NOTES:  Applies in a tactical environment but will likely not be available in mobile field locations.  Such documentation should be available for inspection at a location where supporting headquarters staff (ISSM, SM) would logically be located. Observations and comments may be entered, even if there is no finding.'
  desc 'fix', 'Documentation must exist for the initial request for PDS approval and any modification requests.

PDS must be recertified when modified or when the threat level or security posture changes.

A standard operating procedure (SOP) to ensure proper installation, maintenance, operation and inspection of the PDS must be developed by the PDS owner, approved by the AO, and approved by the cognizant security authority. *The SOP must be submitted as a part of the PDS approval documentation.

PDS approval documentation and all updates should be kept for the lifetime of the physical structure of the PDS.

If the initial documentation or modification requests were not prepared or documentation cannot be located the fix is to prepare a request for PDS approval IAW the CNSSI 7003 template at Annex A and submit to the approving authority for approval.'
  impact 0.3
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49170r769877_chk'
  tag severity: 'low'
  tag gid: 'V-245739'
  tag rid: 'SV-245739r822806_rule'
  tag stig_id: 'CS-05.03.02'
  tag gtitle: 'CS-05.03.02'
  tag fix_id: 'F-49125r769878_fix'
  tag 'documentable'
  tag legacy: ['V-30975', 'SV-41019r3_rule']
end
