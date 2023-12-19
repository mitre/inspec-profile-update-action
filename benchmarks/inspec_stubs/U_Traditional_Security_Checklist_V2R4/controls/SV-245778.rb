control 'SV-245778' do
  title 'Information Assurance - Accreditation Documentation'
  desc 'Failure to provide the proper documentation can lead to a system connecting without all proper safeguards in place, creating a threat to the networks.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Encl A, para 2.; Encl B, para 6.f.; Encl C, para 3, 6.d.(2), 20.e.(1)(a)&(b), 24.e and 18a .

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
PM-1, PM-9, PM-10, AC-3 AC 3(1), AC 3(2), AC-20, RA-2 and CA-6

DODI 8500.01, SUBJECT: Cybersecurity, March 14, 2014 , Encl 3, para 2.a.(1), 9.a.(1)(c), 9.b.(13)

DOD Manual 5200.01, Volume 3, SUBJECT: DOD Information Security Program: Protection of Classified Information, Encl 4, para 8.a.; Encl 7, para 4.c.

DOD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 8, Section 2.
 
DOD Instruction 8510.01, SUBJECT: Risk Management Framework (RMF) for DOD Information Technology (IT), Encl 2, para 7.f & 7.g.; Encl 4, para 1.b.(2)(e); Encl 6, paragraphs 1.b.(1), 2., and 2.e.(4)(a)-(e).

CJCSI 6211.02D, DEFENSE INFORMATION SYSTEMS NETWORK (DISN) RESPONSIBILITIES,
para 7.1.; Encl B, para 2.b.(1), 2.c.(1), 2.f.; Encl C, para 2.a., 5.b., 6.b.(5), 6.c., 6.e.(4), 7.c.(2), 11.a.(3)(g)&(j); Encl D, para 2.b., 4.f.(5), 5.a.(5), 5.j.(1) 7.a, 8., and 12.a&b.

CNSSP No.29, May 2013, National Secret Enclave Connection Policy

DISN Connection Process Guide:
http://disa.mil/network-services/enterprise-connections/connection-process-guide'
  desc 'check', "Check the accreditation package with only a cursory review to ensure the ATO/IATO are current. 

1. Check the SIPRNet/NIPRNet connection approval package. Conduct a cursory review for any traditional security issues. 

2. Ensure the approvals are current. The approvals must come from the DISN Connection Approval Office (CAO). 

TACTICAL ENVIRONMENT: The check is applicable. The ATO and associated documentation should be found in a fixed HQ location where the ISSM/ISSO are located. When possible, documentation should be requested/sought before departing on trips to tactical locations. Copies sent to the reviewer's email (NIPR or SIPR depending on classification of document) can be used to validate compliance.

Note: If any one of the approvals is missing, this is a finding."
  desc 'fix', '1. A current accreditation document approved by the AO must be available for all systems and applications connected to the DODIN. 

2. Copies of the original accreditation documentation along with any subsequent modifications must be available for review. 

3. The Approval to Operate (ATO) or Interim Approval to Operate (IATO) must be up to date and must be signed by the current Approving Authority.

4. Check to ensure the site provided the DISN Connection Approval Office (CAO) current certification documentation IAW CAO guidance. 

5. Check to ensure the site also has notified the CAO of any changes/modification to the approved architecture. 

6. Check to ensure the Approval to Connect (ATC) or Interim Approval to Connect (IATC) for both SIPRNet/NIPRNet are current.'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49209r917194_chk'
  tag severity: 'medium'
  tag gid: 'V-245778'
  tag rid: 'SV-245778r917335_rule'
  tag stig_id: 'IA-07.02.01'
  tag gtitle: 'IA-07.02.01'
  tag fix_id: 'F-49164r917195_fix'
  tag 'documentable'
  tag legacy: ['V-31084', 'SV-41139r3_rule']
end
