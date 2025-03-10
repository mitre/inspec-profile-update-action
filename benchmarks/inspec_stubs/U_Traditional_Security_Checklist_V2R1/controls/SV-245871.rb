control 'SV-245871' do
  title 'Security and Cybersecurity Staff Appointment, Training/Certification and Suitability'
  desc 'Failure to formally appoint security personnel and detail responsibilities, training and other requirements in the appointment notices could result in a weaken security program due to critical security and information assurance personnel not being fully aware of the scope of their duties and responsibilities or not being properly trained or meeting standards for appointment to assigned positions.

REFERENCES:

DoD 8570.01-M, Information Assurance Workforce Improvement Program, 19 December 2005, Incorporating Change 4, 11/10/2015
Chap 3, para C3.2.4.4., Chap 4 para C4.2.3.6., Chap 5 para C5.1.1. and Chap 10 para C10.2.3.6. 

DoD Manual 5200.02, PROCEDURES FOR THE DOD PERSONNEL SECURITY PROGRAM (PSP), Effective: April 3, 2017
Section 2, paragraph 2.10.a., h. & i. and Appendix 7A: Determination Authorities

NIST Special Publication 800-53 (SP 800-53) 
Controls: PM-2, PS-2, PS-3, AC-5, AC-6(5), PM-10, CA-6 and AT-3 

DoD Manual 5200.01, Volume 1, 24 February 2012, SUBJECT: DoD Information Security Program: Overview, Classification, and Declassification 
Encl 2, para 6.b., 7., 7.c., 8.b., 8.c., 8.d., 9. & 12.; Encl 3 para 6.a., 6.b. & 6.b.(5); and Definitions, pg 76 activity SM 

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), 9 February 2011 
Encl C, paragraphs 3.a.(1) (2)(a)(b), 4.a. through 4.e., 26.(c), & 27. and Encl A para 11.b. 

DoD 5200.22-M (NISPOM), February 2006, Incorporating Change 2, May 18, 2016
Paragraphs: 1-201., 2-103.c., 2-306.d., 3-102., & 8-103 

DoDI 8500.01, March 14, 2014, SUBJECT: Cybersecurity
Enclosure 2, paragraph 1.c., 13.c. and Enclosure 3, paragraph 13.b., 16.a.(2), 18.d.

'
  desc 'check', 'Check #1. Check to ensure there are appointment letters for all security staff members including the SM, AO, ISSM, ISSOs, System Administrators (SA), and Network Security Officers (NSO). (CAT III)

Check #2. Check to ensure the appointments are current and an appropriate authority has made the appointments. (CAT III)

Check #3. Check to ensure that pertinent duties, responsibilities, training/certification and other suitability requirements for the appointed positions are contained in the appointment order.  (CAT III)

Check #4. Check supporting documentation to ensure that security staff have been properly trained and certified  for the positions to which they are appointed (e.g. IAM I, II or III for ISSM/ISSO) and that they meet all applicable requirements for the positions.  For instance the AO and ISSM must be US Citizens. (CAT II)       

TACTICAL ENVIRONMENT: The check is applicable for fixed (established) tactical processing environments.  Not applicable to a field/mobile environment.'
  desc 'fix', '1. Ensure there are appointment letters for all Traditional Security staff and Cybersecurity staff members including the SM, DAA, IAM, IAOs, System Administrators (SA), and Network Security Officers (NSO). 

2. Ensure the appointments are current and appropriate authorities have made the appointments.

3. Ensure that pertinent duties, responsibilities, training/certification and other suitability requirements for the appointed positions are contained in the appointment order.  

4. Ensure that security staff have been properly trained and certified for the positions to which they are appointed (e.g. IAM I, II or III for ISSM/ISSO) and that they meet all applicable requirements for the positions.  For instance the AO and ISSM must be US citizens.'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49302r770273_chk'
  tag severity: 'medium'
  tag gid: 'V-245871'
  tag rid: 'SV-245871r770275_rule'
  tag stig_id: 'SM-01.03.01'
  tag gtitle: 'SM-01.03.01'
  tag fix_id: 'F-49257r770274_fix'
  tag satisfies: ['Security and Cybersecurity Staff Appointment', 'Training/Certification and Suitability']
  tag 'documentable'
  tag legacy: ['V-32605', 'SV-42942r3_rule']
end
