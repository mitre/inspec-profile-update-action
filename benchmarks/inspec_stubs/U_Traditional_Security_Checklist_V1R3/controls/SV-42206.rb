control 'SV-42206' do
  title 'Marking Classified - Local or Enclave Classified Marking Procedures must be developed to ensure employees are familiar with appropriate organization Security Classification Guides (SCG), how to obtain guidance for marking classified documents, media and equipment, and where associated forms, classified cover sheets, labels, stamps, wrapping material for classified shipment, etc. can be obtained.'
  desc 'Failure to properly mark classified material could result in the loss or compromise of classified
information.

REFERENCES:

The Information Security Oversight Office (ISOO): http://www.archives.gov/isoo/   Implementing Directive for Protection of Classified (for Executive Order 13526), 32 CFR Parts 2001 and 2003 Classified National Security Information: paragraph 2001.23 Classification marking in the electronic environment.

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraphs 21.a.and 21.g.(1). 

NIST Special Publication 800-53 (SP 800-53), Rev 4, Control: MP-1, MP-3, & AC-16.

DoD Manual 5200.01, Volume 1, 24 February 2012, SUBJECT: DoD Information Security Program: Overview, Classification, and Declassification; Enclosure 2, paragraph 9.

DoD Manual 5200.01, Volume 2, 24 February 2012, SUBJECT: DoD Information Security Program: Marking of Classified Information; paragraph 5.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 201, Chapter 4, Section 2, and Chapter 8, Section 3, paragraphs 8-301.d. and 8-302.g.(1)'
  desc 'check', 'Check to  ensure the local site/enclave security manager has developed written procedures on proper marking of classified documents / media/ equipment.  These procedures should primarily involve guidance for employees concerning what to mark, how to mark items, where classified labels, stamps and other marking tools and supplies are located, etc.  Reference to DoD or component marking guides should be in the local procedures with information on how/where to obtain copies.
                               
TACTICAL ENVIRONMENT:  This check is applicable in a tactical environment if classified documents or media are created/extracted from the SIPRNet.  The only exception will be for urgent (short term) tactical operations or other contingency situations where fixed facilities and equipment are not yet present or incapable of being used. All deployed SIPRNet equipment should already contain applicable classification markings/labels.'
  desc 'fix', 'Ensure the local site/enclave security manager has developed written procedures on proper marking of classified documents / media/ equipment.  These procedures should primarily involve guidance for employees concerning what to mark, how to mark items, where classified labels, stamps and other marking tools and supplies are located, etc.  Reference to DoD or component marking guides should be in the local procedures with information on how/where to obtain copies.'
  impact 0.3
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-40608r4_chk'
  tag severity: 'low'
  tag gid: 'V-31909'
  tag rid: 'SV-42206r3_rule'
  tag stig_id: 'IS-03.03.01'
  tag gtitle: 'Marking Classified - Local or Enclave Classified Marking Procedures'
  tag fix_id: 'F-35847r2_fix'
  tag 'documentable'
end
