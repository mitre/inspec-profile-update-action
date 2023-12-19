control 'SV-245836' do
  title 'Destruction of Classified Documents Printed from the SIPRNet Using Approved Devices on NSA Evaluated Products Lists (EPL).'
  desc 'Failure to properly destroy classified material can lead to the loss or compromise of classified or sensitive information.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 29.h.(1) & 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: MP-1, MP-6, PE-1.

DoDI 8500.01, SUBJECT: Cybersecurity, March 14, 2014 

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information: Enclosure 3 paragraphs 17, 18, & 19.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, paragraphs 5-704, 5-705 & 5-708.

http://www.nsa.gov/ia/guidance/media_destruction_guidance/index.shtml'
  desc 'check', 'General Guidance:  Classified documents and paper material identified for destruction shall be destroyed completely, to prevent anyone from reconstructing the classified information. Effective January 1, 2011, only equipment listed on an evaluated products list (EPL) issued by NSA may be used to destroy classified information.

(1) Equipment approved for use prior to January 1, 2011, and not found on the appropriate EPL may be used for destruction of classified information until December 31, 2016.

(2) Unless determined otherwise by NSA, whenever an EPL is revised, equipment removed from the EPL may be utilized for destruction of classified information for up to 6 years
from the date of its removal from the EPL.

(3) In all cases, if any such previously approved equipment needs to be replaced or otherwise requires a rebuild or replacement of a critical assembly (e.g., shredder blade
assembly), the unit must be replaced with one listed on the appropriate EPL.

The EPLs and further guidance may be obtained by calling (410) 854-6358 or at http://www.nsa.gov/ia/guidance/media_destruction_guidance/index.shtml.

Checks:   

Check #1. Check that only crosscut shredders listed on an EPL for High Security Crosscut Paper Shredders are used to destroy classified material. 

Check #2. Check that only pulverizers, disintegrators and pulping (wet process) devices listed on an EPL are used to destroy classified water-soluble material.  

Check #3.  Check to ensure that burn bags (if used to store classified paper awaiting destruction at a central destruction facility) are sealed and safeguard in a safe or vault or area approved for classified open storage until actually destroyed.  

NOTE:  Recommend that reviewers check shredded material, no matter how new or old the shredder appears to be.  Look to determine if it is readily apparent the shred material is "not within specifications" due to lack of maintenance, bad teeth, etc., This discovery can result in a finding.

TACTICAL ENVIRONMENT: Applies in all environments whenever classified documents are to be destroyed.'
  desc 'fix', 'General Guidance:  Classified documents and paper material identified for destruction shall be destroyed completely, to prevent anyone from reconstructing the classified information. Effective January 1, 2011, only equipment listed on an evaluated products list (EPL) issued by NSA may be used to destroy classified information.

1. Equipment approved for use prior to January 1, 2011, and not found on the appropriate EPL may be used for destruction of classified information until December 31, 2016.

2. Unless determined otherwise by NSA, whenever an EPL is revised, equipment removed from the EPL may be utilized for destruction of classified information for up to 6 years
from the date of its removal from the EPL.

3. In all cases, if any such previously approved equipment needs to be replaced or otherwise requires a rebuild or replacement of a critical assembly (e.g., shredder blade
assembly), the unit must be replaced with one listed on the appropriate EPL.

The EPLs and further guidance may be obtained by calling (410) 854-6358 or at
 http://www.nsa.gov/ia/guidance/media_destruction_guidance/index.shtml.

Fixes:

1. Only crosscut shredders listed on an EPL for High Security Crosscut Paper Shredders can be used to destroy classified material. 

2. Only pulverizers, disintegrators and pulping (wet process) devices listed on an EPL can be used to destroy classified water-soluble material.  

3. Burn bags (if used to store classified paper awaiting destruction at a central destruction facility) must be sealed and safeguard in a safe or vault or area approved for classified open storage until actually destroyed.'
  impact 0.7
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49267r770168_chk'
  tag severity: 'high'
  tag gid: 'V-245836'
  tag rid: 'SV-245836r770170_rule'
  tag stig_id: 'IS-11.01.01'
  tag gtitle: 'IS-11.01.01'
  tag fix_id: 'F-49222r770169_fix'
  tag 'documentable'
  tag legacy: ['V-32009', 'SV-42325r3_rule']
end
