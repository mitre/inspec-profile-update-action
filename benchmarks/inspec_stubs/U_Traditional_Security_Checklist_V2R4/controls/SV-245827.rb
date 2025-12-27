control 'SV-245827' do
  title 'Handling of Classified Documents, Media, Equipment - Written Procedures and Training  for when classified material/equipment is removed from a security container and/or secure room.'
  desc 'Failure to develop procedures and to train employees on protection of classified when removed from storage could lead to the loss or compromise of classified or sensitive information due to a lack of employee knowledge of requirements.

REFERENCES:

The Information Security Oversight Office (ISOO): http://www.archives.gov/isoo/   Implementing Directive for Protection of Classified (for Executive Order 13526), 32 CFR Parts 2001 and 2003 Classified National Security Information: Subpart G-Security Education and Training

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Control: MP-1.

DoD Manual 5200.01, Volume 1, 24 February 2012, SUBJECT: DoD Information Security Program: Overview, Classification, and Declassification, Enclosure 2, paragraphs 9. c., d., f., j., & k. and 12.a.

DoD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DoD Information Security Program: Protection of Classified Information; Enclosure 2, paragraphs 14 & 15; Enclosure 5, paragraphs 3.a.(2), 3.c.(2)(a) & (b), 3.d.(4), and 7.a. and Enclosure 7, paragraph 10.

DoD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 5 and Chapter 8, Section 1, paragraph 8-103.a.

'
  desc 'check', '1. Check there are written procedures for handling classified material/equipment when removed from a security container and/or secure room.  These procedures must thoroughly cover all aspects of protection and storage of classified materials and be made readily available to each employee via electronic means, such as in space on an organizational intranet, shared folders or other means available. (CAT III)

2. Check training logs (initial and annual refresher) that all employees granted access to classified are briefed on proper handling procedures e.g., use of cover sheets, maintaining positive control of the material, marking/labeling, access by vendors, determining clearance and need-to-know before release, reproduction, etc. (CAT III) 

TACTICAL ENVIRONMENT: The check is applicable for fixed tactical classified processing environments. Not applicable to a field/mobile environment.'
  desc 'fix', 'There must be written procedures for handling classified material/equipment when removed from approved storage (security container and/or secure room, vault, collateral classified open storage area or SCIF). 

The procedures must be readily available to each employee via electronic means, such as in space on an organizational intranet, shared folders or other means available 

Training logs (initial and annual refresher) must reflect that all employees granted access to classified are briefed on proper handling procedures e.g., use of cover sheets, maintaining positive control of the material, marking/labeling, access by vendors, determining clearance and need-to-know before release, reproduction, etc.'
  impact 0.3
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49258r770141_chk'
  tag severity: 'low'
  tag gid: 'V-245827'
  tag rid: 'SV-245827r822884_rule'
  tag stig_id: 'IS-07.03.01'
  tag gtitle: 'IS-07.03.01'
  tag fix_id: 'F-49213r770142_fix'
  tag satisfies: ['Handling of Classified Documents', 'Media', 'Equipment - Written Procedures and Training']
  tag 'documentable'
  tag legacy: ['SV-42287r3_rule', 'V-31988']
end
