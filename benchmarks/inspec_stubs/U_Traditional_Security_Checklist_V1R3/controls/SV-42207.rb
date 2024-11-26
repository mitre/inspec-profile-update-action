control 'SV-42207' do
  title 'Marking Classified - Equipment, Documents or Media:  In a classified operating environment, all unclassified items must be marked in addition to all classified  items.'
  desc 'Failure to properly mark classified material could result in the loss or compromise of classified information.

REFERENCES:

The Information Security Oversight Office (ISOO): http://www.archives.gov/isoo/   Implementing Directive for Protection of Classified (for Executive Order 13526), 32 CFR Parts 2001 and 2003 Classified National Security Information: paragraph 2001.23 Classification marking in the electronic environment.

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure A, paragraph 6.a. and Enclosure C, paragraphs 21.h.(7) & 29.a. 

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: AC-16 and MP-3.

DoD Manual 5200.01, Volume 2, 24 February 2012, SUBJECT: DoD Information Security Program: Marking of Classified Information; Enclosure 2, paragraph 4.b.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 201, Chapter 4, Section 2, paragraphs 4-201, 4-202, 4-203 and Chapter 8, Section 3, paragraph 8-302.g.(1)'
  desc 'check', 'Check to ensure ALL equipment/media/documents in the areas housing SIPRNet assets contain proper classification markings.  

In a classified operating environment, all unclassified items must be marked in addition to all classified items.  For instance: In areas where any classified equipment such as servers, client workstations, printers, routers, crypto, etc. are being used - all classified equipment, media and documents must be properly marked with classification levels and handling caveats - AND ALL UNCLASSIFIED equipment (servers, client workstations, printers, routers, crypto, etc.), media and documents must also be properly marked as unclassified and with handling caveats such as FOUO, when appropriate.  This total marking of all assets in a classified environment eliminates the assumption that anything not marked is unclassified.  Hence, all equipment, media and documents within SCIFs, Vaults, Secure Rooms and classified Controlled Access Areas (CAA) must be marked with classification levels and handling caveats.

SPECIAL NOTE FOR MONITORS:  Monitors connected to SIPRNet/NIPRNet are inert items of equipment in that they do not store/retain classified data.  Typically, in a mixed classified/unclassified environment it is appropriate to physically label a monitor classification based on the system to which it is connected.
         
If a classification banner is displayed on an active monitor screen then the physical monitor is not required to have a SF 710 (unclassified) or SF  707 (secret) sticker.  Regardless, there is no prohibition against also using the SF labels as an additional identifier but it is not required.  

Typically, most monitor screens connected to the DISN do have classification banners displayed - so placement of SF stickers on monitors is practically a non-issue.  

Also, consider that many workstations are using KVM switches to share monitor screens between NIPRNet and SIPRNet.  Hence, the single monitor will be unclassified or classified depending on the network it is connected to at a particular moment; making placement of physical classification labels impractical. 
                        
TACTICAL ENVIRONMENT:  This check is applicable in a tactical environment if classified documents or media are created/extracted from the SIPRNet.  The only exception will be for urgent (short term) tactical operations or other contingency situations where fixed facilities and equipment are not yet present or incapable of being used. All deployed SIPRNet equipment should already contain applicable classification markings/labels.'
  desc 'fix', 'Ensure ALL equipment/media/documents in the areas housing SIPRNet assets contain proper classification markings.  In a classified operating environment, all unclassified items must be marked in addition to all classified items.  For instance: In areas where any classified equipment such as servers, client workstations, printers, routers, crypto, etc. are being used - all classified equipment, media and documents must be properly marked with classification levels and handling caveats - AND ALL UNCLASSIFIED equipment (servers, client workstations, printers, routers, crypto, etc.), media and documents must also be properly marked as unclassified and with handling caveats such as FOUO, when appropriate.  This total marking of all assets in a classified environment eliminates the assumption that anything not marked is unclassified.  Hence, all equipment, media and documents within SCIFs, Vaults, Secure Rooms and classified Controlled Access Areas (CAA) must be marked with classification levels and handling caveats. 

SPECIAL NOTE FOR MONITORS:  Monitors connected to SIPRNet/NIPRNet are inert items of equipment in that they do not store/retain classified data.  Typically, in a mixed classified/unclassified environment it is appropriate to physically label a monitor classification based on the system to which it is connected.
         
If a classification banner is displayed on an active monitor screen then the physical monitor is not required to have a SF 710 (unclassified) or SF  707 (secret) sticker.  Regardless, there is no prohibition against also using the SF labels as an additional identifier but it is not required.  

Typically, most monitor screens connected to the DISN do have classification banners displayed - so placement of SF stickers on monitors is practically a non-issue.  

Also, consider that many workstations are using KVM switches to share monitor screens between NIPRNet and SIPRNet.  Hence, the single monitor will be unclassified or classified depending on the network it is connected to at a particular moment; making placement of physical classification labels impractical.'
  impact 0.5
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-40609r7_chk'
  tag severity: 'medium'
  tag gid: 'V-31910'
  tag rid: 'SV-42207r3_rule'
  tag stig_id: 'IS-03.02.01'
  tag gtitle: 'Marking Classified - Equipment, Documents or Media'
  tag fix_id: 'F-35848r4_fix'
  tag 'documentable'
end
