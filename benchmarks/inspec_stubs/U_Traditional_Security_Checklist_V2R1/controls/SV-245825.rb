control 'SV-245825' do
  title 'Storage/Handling of Classified Documents, Media, Equipment - must be under continuous personal protection and control of an authorized (cleared) individual OR guarded or stored in an approved locked security container (safe), vault, secure room, collateral classified open storage area or SCIF.'
  desc 'Failure to store classified in an approved container OR to properly protect classified when removed from storage can lead to the loss or compromise of classified or sensitive information.

REFERENCES:

The Information Security Oversight Office (ISOO): http://www.archives.gov/isoo/   Implementing Directive for Protection of Classified (for Executive Order 13526), 32 CFR Parts 2001 and 2003 Classified National Security Information: paragraph 2001.41 Responsibilities of holders. and 2001.43 Storage.

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraphs 15.b.(1), 21.d., 24.j., and 34.c.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Control: MP-4.

DoD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DoD Information Security Program: Protection of Classified Information; Enclosure 2, paragraphs 2 & 8 and Enclosure 3, paragraph 3.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 8, Section 3, paragraphs 8-302.b. and g.

'
  desc 'check', %q(1. In areas containing SIPRNet assets - Check to ensure that classified documents, information system (IS) equipment and removable media that is not under the direct personal control and observation of an authorized person is guarded or stored in a locked security container (GSA approved safe), vault, secure room, collateral classified open storage area or SCIF with protection equal to or exceeding the highest classification of the material/equipment.  (CAT I)

2. Check to ensure that site security personnel develop written procedures for response to incidents of classified materials found not in secure storage or under continuous observation and control of a cleared employee and make the procedures readily available to each employee via electronic means, such as in space on an organizational intranet, shared folders or other means available. (CAT III)

Procedures for response to classified materials discovered that are not in proper storage or under proper control of a cleared person must include the following:

  a.  Site security personnel, security reviewers/inspectors, employees or anyone making discovery of classified material not in secure storage or under continuous observation and control of a cleared employee immediately take control and properly secure the classified materials not under proper control when not in approved storage.  Second they must report the discovery to their supervisory chain and/or site security officials.  (CAT III)

  b.  Site security personnel must initiate a preliminary inquiry if appropriate to determine the cause of the improperly secure material and to determine if any material was lost or compromised (security incident).  (CAT III)

  c.  Site security personnel must conduct remedial training action subsequent to incidents of classified materials found not in secure storage or under continuous observation and control of a cleared employee to remind employees of procedures and requirements to maintain positive control of classified materials removed from approved storage.  (CAT III)

  d.  Site managers/supervisors must discipline employees, as appropriate who do not comply with appropriate requirements to maintain positive control of classified material they have removed from secure storage. (CAT III)

3. Check to ensure that's site security personnel conduct initial and annual training to indoctrinate and remind employees of procedures and requirements to maintain positive control of classified materials removed from approved storage and measures to take upon discovery of classified material not in proper storage or under proper control of a cleared person. (CAT II)

Suggested methodology for reviewers:
During the review/walk-around be observant for classified materials (documents media, and equipment) that have been removed from approved storage.  Specifically look to determine if employees are maintaining positive control of the material.  Unless a properly cleared employee is able to clearly see and control the material - this will be a finding.

The employee(s) must be specifically aware the classified material is in their area AND that they are responsible for ensuring it is controlled/protected.  Just having cleared employee(s) "in the area" of the classified material or assuming other cleared employees in the area are responsible for the classified material is not sufficient control.

An example of a possible finding is when someone working on a classified system departs their work space (cube environment) for lunch or other type of break and does not ask another cleared employee to take control of their classified equipment, documents or media OR does not place the classified hard drive, classified documents and classified media in approved storage.

TACTICAL ENVIRONMENT:  This check is applicable in a tactical environment.

The only exception will be where there is a lack of permanent storage solutions for urgent (short term) tactical operations or other contingency situations.  Primarily this involves field/mobile environments where fixed facilities and equipment are not yet present or incapable of being used.  However, all classified equipment, documents or media not properly stored in a safe, vault or secure room must still be under the continuous observation and control of an appropriately cleared person.)
  desc 'fix', 'Primary Requirements for Control of Classified Material:
Classified documents, information system (IS) equipment and removable media must be:

1. Under the direct personal control and observation of an authorized person, who possesses a security clearance and need-to know equal to or greater than the classified information or material being controlled.  The properly cleared employee(s) must be able to clearly see and control the classified material.  The employee(s) must be specifically aware the classified material is in their area AND that they are responsible for ensuring it is protected.

or

2.  Guarded by a trained professional security official who possesses a security clearance equal to or greater than the classified information or material being controlled. 

or

3. Stored in a locked security container (GSA approved safe), vault, secure room, collateral classified open storage area or SCIF with protection equal to or exceeding the highest classification of the material/equipment. 

Secondary Requirements:

Actions to enhance protection of classified materials:

1.  Site security personnel must conduct initial and annual training to indoctrinate and remind employees of procedures and requirements to maintain positive control of classified materials removed from approved storage. 

2.  Site security personnel must develop written procedures for protection and storage of classified materials and make the procedures readily available to each employee via electronic means, such as in space on an organizational intranet, shared folders or other means available.  

3. Site security personnel must conduct regular checks of their areas of responsibility and constantly be observant to ensure that classified materials (documents media, and equipment) that have been removed from approved storage are under the continuous personal observation and control of cleared persons.  

Tertiary Requirements:

Required Actions upon discovery of classified material not in secure storage or under continuous observation and control of a cleared employee:

1.  Site security personnel, security reviewers/inspectors, employees or anyone making discovery of classified material not in secure storage or under continuous observation and control of a cleared employee must immediately take control and properly secure any classified materials not under proper control when not in approved storage.  Second they must report the discovery to their supervisory chain and/or site security officials. 
 
2.  Site security personnel must initiate a preliminary inquiry if appropriate to determine the cause of the improperly secure material and to determine if any material was lost or compromised (security incident).  

3.  Site security personnel must develop written procedures for response to incidents of  classified materials found not in secure storage or under continuous observation and control of a cleared employee and make the procedures readily available to each employee via electronic means, such as in space on an organizational intranet, shared folders or other means available.  

4.  Site security personnel must conduct remedial training action subsequent to incidents of classified materials found not in secure storage or under continuous observation and control of a cleared employee to remind employees of procedures and requirements to maintain positive control of classified materials removed from approved storage.  

5.  Site managers/supervisors must discipline employees, as appropriate who do not comply with appropriate requirements to maintain positive control of classified material they have removed from secure storage.'
  impact 0.7
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49256r770135_chk'
  tag severity: 'high'
  tag gid: 'V-245825'
  tag rid: 'SV-245825r770137_rule'
  tag stig_id: 'IS-05.01.01'
  tag gtitle: 'IS-05.01.01'
  tag fix_id: 'F-49211r770136_fix'
  tag satisfies: ['Storage/Handling of Classified Documents', 'Media', 'Equipment']
  tag 'documentable'
  tag legacy: ['V-31986', 'SV-42285r3_rule']
end
