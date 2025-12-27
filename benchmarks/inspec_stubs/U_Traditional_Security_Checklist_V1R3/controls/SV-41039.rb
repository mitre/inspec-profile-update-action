control 'SV-41039' do
  title 'Industrial Security - DD Form 254'
  desc 'Failure to complete a DD Form 254 (Contract Security Classification Specification) or to specify security clearance and/or IT requirements for all contracts that require access to classified material can result in unauthorized personnel having access to classified material or mission failure if personnel are not authorized the proper access.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Encl A, Para 11, Encl B, para 4.h & 4.i., Encl C, para 5. (a, b & c), Encl C, para 26.g.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
PE-2, PE-2(1), PE-3, PE-8, , PS-3(1), PS-6(2), PS-7

DoD Manual 5200.01, Volume 4, SUBJECT: DoD Information Security Program: Controlled Unclassified Information (CUI), Encl 3, para 1.e.

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information, Encl 2, para 18.i.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 8, paragraph 8-302.a., b., g.& j, and paragraph 8-303.a and b. 

DoD Manual 5220.22, Volume 2, National Industrial Security Program: Industrial Security Procedures for Government Activities, 1 August 2018, Section 3, paragraph 3.4.a. and Section 6.
 
DoD Instruction 8510.01, SUBJECT: Risk Management Framework (RMF) for DoD Information Technology (IT): Encl 2, para 7.l., Encl 3, para 3.b.(3), Encl 6, para 1.b.(5)(a)&(c)&(d) and para 2.c(c).

DoD Instruction 8500.01, SUBJECT: Cybersecurity: Encl 2, para 13.i., j & l. and Encl 3, para 7.f., k., & l, para 9.b(4) and para 10.d.

CJCSI 6211.02D, DEFENSE INFORMATION SYSTEMS NETWORK (DISN) RESPONSIBILITIES, Encl B, para 2.c.(7) and para 7., Encl C, para 6.b(7)(a) &(b), Encl D, para 2.j.

DoD 8570.01-M, Information Assurance Workforce Improvement Program, paragraphs: C1.4.4.5, C1.4.4.12., C2.3.9., C3.2.4.4., C3.2.4.8., C3.2.4.8.1., C4.2.3.7.1., C7.3.4., C10.2.3.7.1., C11.2.4.7.1.'
  desc 'check', "1. Check there are DD Forms 254 available for all classified contracts. 

NOTE: These forms may be held by the site contracting officials but should be available to the site security manager and information security manager for review.

2. Conduct a cursory review of the DD 254 to ensure all security requirements are properly detailed on the form, especially with regard to Information Assurance (ie., IT Position level designation) in addition to security clearance, training and certification requirements. 

NOTE: Applicable to tactical environments if there are contractor personnel performing classified work. This form will likely only be found at fixed locations rather than field locations. While the DD 254 may not be available on site or even in Theater, the completed document's location should be identified and if possible a scanned and emailed copy requested for review. This will likely only be able to occur via SIPRNet email because some of these forms contain classified information, while all others are only FOUO."
  desc 'fix', '1. DD Forms 254 must be on hand for each classified contract. 

2. All security requirements must be properly detailed on the form, particularly for Information Technology related requirements, such as IT Position levels (in addition to security clearance, training and certification requirements)for the positions or types of work to be performed.'
  impact 0.5
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-39660r6_chk'
  tag severity: 'medium'
  tag gid: 'V-30993'
  tag rid: 'SV-41039r3_rule'
  tag stig_id: 'ID-01.02.01'
  tag gtitle: 'Industrial Security - DD Form 254'
  tag fix_id: 'F-34805r6_fix'
  tag 'documentable'
end
