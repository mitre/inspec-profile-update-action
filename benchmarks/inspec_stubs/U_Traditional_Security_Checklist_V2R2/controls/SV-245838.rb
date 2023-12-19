control 'SV-245838' do
  title 'Classified Destruction - Hard Drive and Storage Media Sanitization Devices and Plans are not Available for disposal of Automated Information System (AIS) Equipment On-Hand'
  desc 'Failure to properly destroy classified material can lead to the loss or compromise of classified or
sensitive information.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraphs 21.h.(9); 28; 29b.,d.(1)&(2).h.(1)&(2) and para 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: MP-1, MP-6, PE-1.

DoDI 8500.01, SUBJECT: Cybersecurity, March 14, 2014, Enclosure 3, paragraph 9.b.(8) & (9) 

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information: Enclosure 2, paragraph 14 & 14(d); Enclosure 3 paragraphs 17, 18, & 19; Enclosure 5, paragraph 3.d.(3); Enclosure 7, paragraph 6.

Assistant Secretary of Defense for Command, Control, Communications and Intelligence Memorandum, "Disposition of Unclassified DoD Computer Hard Drives," June 4, 2001

DoD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016, paragraphs 5-704, 5-705, 5-706, 5-707,  5-708, 8-202.e. & 8-302.g.

NIST SP 800-88, Guidelines for Media Sanitization

NSA/CSA Policy Manual 9-12, NSA/CSS Storage Device Declassification Manual

http://www.nsa.gov/ia/guidance/media_destruction_guidance/index.shtml'
  desc 'check', 'Check to ensure there is equipment and/or plans for the destruction of classified or sensitive systems and media used by the site or organization. Lack of appropriate equipment to properly sanitize the classified media used or lack of plans for disposal and/or proper protection in transit to a disposal facility will result in a finding. 

Checks:

Check #1.  If used by the site are hard drive and tape degaussers  periodically tested and certified as required by the manufacturer?

Check #2.  Are appropriate wipe products available for classified systems or spillage incidents?
  
Check #3.  Is there an approved product (such as the Whitaker Brothers Inc. Datastroyer) on-hand to properly remove readable surfaces from optical media such as CDs or DVDs?
 
Check #4.  Is all obsolete classified equipment and media  properly secured in a safe, vault or secure room until properly disposed of?  (Note:  This would be a CAT I finding under the appropriate "storage" vulnerability)
 
Check #5.  In the event the site has limited or no destruction equipment: Are there plans or arrangements to take classified material to NSA for proper disposal or another DoD organization who has destruction equipment and has agreed to provide support for destruction of classified?

Check #6.  Are there appropriate transportation and/or shipping arrangements to ensure the classified material is properly protected while in transit to the destruction facility? 
                                                    TACTICAL ENVIRONMENT: Applies in all environments whenever classified documents or materials are to be destroyed.'
  desc 'fix', 'Ensure there is equipment and/or plans for the destruction of classified or sensitive systems and media used by the site or organization. 

Considerations:

1.  If used by the site are hard drive and tape degaussers  periodically tested and certified as required by the manufacturer?

2.  Are appropriate wipe products available for classified systems or spillage incidents?
  
3.  Is there an approved product (such as the Whitaker Brothers Inc. Datastroyer) on-hand to properly remove readable surfaces from optical media such as CDs or DVDs?
 
4.  Is all obsolete classified equipment and media  properly secured in a safe, vault or secure room until properly disposed of?  

5.  In the event the site has limited or no destruction equipment are there plans or arrangements to take classified material to NSA for proper disposal or another DoD organization who has destruction equipment and has agreed to provide support for destruction of classified?

6.  Are there appropriate transportation and/or shipping arrangements to ensure the classified material is properly protected while in transit to the destruction facility?'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49269r770174_chk'
  tag severity: 'medium'
  tag gid: 'V-245838'
  tag rid: 'SV-245838r822901_rule'
  tag stig_id: 'IS-11.02.01'
  tag gtitle: 'IS-11.02.01'
  tag fix_id: 'F-49224r770175_fix'
  tag 'documentable'
  tag legacy: ['V-32102', 'SV-42419r3_rule']
end
