control 'SV-245842' do
  title 'Classification Guides Must be Available for Programs and Systems for an Organization or Site'
  desc 'Failure to have proper classification guidance available for Information Systems and/or associated programs run on them can result in the misclassification of information and ultimately lead to the loss or compromise of classified or sensitive information.

REFERENCES:

The Information Security Oversight Office (ISOO): http://www.archives.gov/isoo/   Implementing Directive for Protection of Classified (for Executive Order 13526), 32 CFR Parts 2001 and 2003 Classified National Security Information: Subpart B - Â§ 2001.15 Classification guides.

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 6.c. and paragraph 26.e.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Control: AC-3, IA-5, MP-5, MP-6, PE-2, PS-3, PS-6.

DoD Manual 5200.01, Volume 1, 24 February 2012, SUBJECT: DoD Information Security Program: Overview, Classification, and Declassification, Enclosure 2, paragraph 9.h.; Enclosure 4; Enclosure 5 and Enclosure 6.

DoD Manual 5200.01, Volume 2, 24 February 2012, SUBJECT: DoD Information Security Program: Marking of Classified Information; Enclosure 3, paragraph 2.a.

DoD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DoD Information Security Program: Protection of Classified Information; Enclosure 6, paragraphs 4, 51 and Glossary.

DoD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016, paragraphs  4-101, 4-102, 4-103 and 7-102.'
  desc 'check', 'Check to ensure the site has all Classification Guides for the systems and programs they are responsible for and/or which are applicable to their operations.  Further, such classification guides and training on the use of them should be made available to employees working with the equipment or systems to which they apply. At a minimum if a site has SIPRNet connections they should have a copy of the most recent SIPRNet Security Classification Guide.

TACTICAL ENVIRONMENT: The check is applicable for fixed (established) tactical processing environments where procedural documents (SOPs) should be in place.  Not applicable to a field/mobile environment.'
  desc 'fix', 'Ensure the site has all Classification Guides for the programs and systems they are responsible for and/or which are applicable to their operations.  Further, such classification guides and training on the use of them should be made available to employees working with the equipment or systems to which they apply. At a minimum if a site has SIPRNet connections they should have a copy of the most recent SIPRNet Security Classification Guide.'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49273r823107_chk'
  tag severity: 'medium'
  tag gid: 'V-245842'
  tag rid: 'SV-245842r823108_rule'
  tag stig_id: 'IS-15.02.01'
  tag gtitle: 'IS-15.02.01'
  tag fix_id: 'F-49228r770187_fix'
  tag 'documentable'
  tag legacy: ['V-32150', 'SV-42467r3_rule']
end
