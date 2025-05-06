control 'SV-245826' do
  title 'Non-Disclosure Agreement - Standard Form 312: no person may have access to classified information unless that person has a security clearance in accordance with DODM 5200.02 and has signed a Standard Form (SF) 312, Classified Information Non-Disclosure Agreement (NDA), and access is essential to the accomplishment of a lawful and authorized Government function (i.e., has a need to know).'
  desc 'Failure to verify clearance and need-to-know and execute a nondisclosure agreement (NDA) before granting access to classified can result in unauthorized personnel having access to classified information.

REFERENCES:

The Information Security Oversight Office (ISOO): http://www.archives.gov/isoo/  Implementing Directive for Protection of Classified (for Executive Order 13526), 32 CFR Parts 2001 and 2003 Classified National Security Information: Subpart H-Standard Forms, Â§ 2001.80 Prescribed standard forms.(d) Standard Forms. (2) SF 312, Classified Information Nondisclosure Agreement:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 11.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Control: PS-3., PS-6. & PS-6.(2).

DOD Manual 5200.01, Volume 1, 24 February 2012, SUBJECT: DOD Information Security Program: Overview, Classification, and Declassification, Enclosure 3, paragraph 11.b.(1).

DOD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DOD Information Security Program: Protection of Classified Information; Enclosure 2, paragraph 3.

DOD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 3, Section 1, paragraph 3-106.

DOD Manual 5200.02, Procedures for the DOD Personnel Security Program (PSP), 3 April 2017, paragraphs 4.10.g.(2)(b), 8.1.b., and 12.1.c.

ISSO Notice 2022-01: Digital Signatures of Standard Form (SF) 312 Classified Nondisclosure Agreement dated May 9, 2022'
  desc 'check', 'The check is to review a sample of Personnel Security Records (minimum of 10 percent assigned military and civilian employees) to ensure SF 312s have been signed by persons granted access to classified information systems. The now outdated SF 189 or SF 189A, if found, are still valid NDAs. The execution of an NDA should also be annotated in the Defense Information System for Security (DISS). If a paper copy is found but the form is not in DISS OR if it is annotated in DISS and a paper copy is not on hand, this is not a finding. 

TACTICAL ENVIRONMENT: This check is applicable in a tactical environment. Anyone with access to classified information must have signed an NDA. Paper copies of the signed NDA will likely not be available in a tactical area of operations; however, system access to DISS should be possible if the theater of operations has been well established.'
  desc 'fix', 'All assigned personnel granted access to classified information must have a signed NDA on record. The execution of an NDA must be annotated in the DISS and a signed hard copy MAY also be available locally. 

Personnel who transfer from other units or organizations will not necessarily have a signed hard-copy NDA on file locally since they are only required to sign the NDA once, but it MUST be reflected in DISS. 

If an NDA is not annotated in DISS and a hard copy is not on hand locally, a new SF 312 must be executed and annotated in DISS.

For individuals without an SF 312 or other approved NDA form on file (either hard copy or in DISS), immediately remove access to classified information systems (i.e., SIPRNet) pending proper execution of an NDA (SF 312) and annotation in DISS.'
  impact 0.3
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49257r917226_chk'
  tag severity: 'low'
  tag gid: 'V-245826'
  tag rid: 'SV-245826r917347_rule'
  tag stig_id: 'IS-06.03.01'
  tag gtitle: 'IS-06.03.01'
  tag fix_id: 'F-49212r917227_fix'
  tag 'documentable'
  tag legacy: ['V-31987', 'SV-42286r3_rule']
end
