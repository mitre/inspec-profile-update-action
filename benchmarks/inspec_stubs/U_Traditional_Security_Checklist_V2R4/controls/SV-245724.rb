control 'SV-245724' do
  title 'COMSEC Account Management - Program Management and Standards Compliance'
  desc 'Recipients of NSA or Service COMSEC accounts are responsible to properly maintain the accounts. Procedures covering security, transport, handling, etc., of COMSEC must be developed to supplement regulatory guidelines. NSA or sponsoring Services of the COMSEC accounts maintain oversight by conducting required inspections. If COMSEC accounts are not properly maintained and findings are noted during an inspection, they must be addressed properly and promptly. If this is not done, the integrity of COMSEC items may be adversely impacted, resulting in the loss or compromise of COMSEC equipment or key material. 

REFERENCES:

DOD Manual 5200.01, Volume 1, 24 February 2012, SUBJECT: DOD Information Security Program: Overview, Classification, and Declassification, Encl 3, paragraph 6.e. (3).

DOD 5220.22-M (NISPOM), Section 4

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: AU-1, CA-1, CA-2, CA-2(1), CA-2(2), CA-2(3), CA-5, CM-3(6), PL-1, PL-2(3), PL-7, SC-1, SC-12, SC-12(1), and SC-13

NSA/CSS Policy Manual 3-16, Sections III, VI, X and XI
 
CNSS Policy No.1, NATIONAL POLICY FOR SAFEGUARDING AND CONTROL OF COMSEC MATERIALS

DOD Instruction 8523.01, Communications Security (COMSEC), January 6, 2021

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND)'
  desc 'check', 'Ask how the COMSEC account is managed. Check for written procedures and inspection reports.

NOTES:

1. Applies in a tactical environment if the crypto equipment and key material being observed is at a location where supporting staff (IAM, SM, COMSEC Custodian) would logically be located. If it is a mobile tactical organization, responsibility for program management might simply be the identification of an individual responsible for keeping track of and maintaining COMSEC materials, but supporting documentation may not be immediately available and should not be written as a finding; however, observations and comments may still be documented. 

2. Note in the report the COMSEC Account type e.g. NSA, Navy, Army, etc. 

3. Note in the report the last COMSEC Inspection Date based on observed documentation. (Summarize the overall results and if the site is taking action to address/correct findings.) 

4. Ensure that any COMSEC account, materials or equipment being inspected is used for encryption of DODIN assets. COMSEC accounts or items not used with DODIN assets should not be inspected.

5. This check is not intended to be an inspection of the COMSEC Program, rather it is a verification that a viable program is in place with NSA or oversight. The idea is to ensure that NSA or Service oversight inspection findings/deficiencies are being corrected in a timely manner by the site.'
  desc 'fix', 'The site must have local procedures covering maintenance of COMSEC equipment and key material. Further, any inspection findings from NSA or Services issuing the account or the account sponsor (for Hand Receipt holders) must be corrected or provide evidence there is a plan of action in place and underway to correct noted deficiencies.'
  impact 0.3
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49155r917139_chk'
  tag severity: 'low'
  tag gid: 'V-245724'
  tag rid: 'SV-245724r917316_rule'
  tag stig_id: 'CS-01.03.02'
  tag gtitle: 'CS-01.03.02'
  tag fix_id: 'F-49110r917140_fix'
  tag 'documentable'
  tag legacy: ['V-30928', 'SV-40970r3_rule']
end
