control 'SV-245799' do
  title 'Information Security (INFOSEC) - Secure Room Storage Standards  Windows - Accessible from the Ground Hardened Against Forced Entry and Shielded from Exterior Viewing of Classified Materials Contained within the Area.'
  desc 'Failure to meet standards for ensuring that there is structural integrity of the physical perimeter surrounding a secure room (AKA: collateral classified open storage area) IAW DoD Manual 5200.01, Volume 3 could result in the undetected loss or compromise of classified material.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraphs 24.j. and 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
MP-4, PE-3, PE-5 and PE-6

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information: Appendix to Encl 3, para 1.b.(4)(a) & (b).

Information Security Oversight Office, 32 CFR Parts 2001 and 2003 Classified National Security Information: paragraph 2001.53 Open storage areas, (d) Windows (1) and (2).

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 5,  Section 8, Construction Requirements, paragraph 5-801.c. Windows.'
  desc 'check', 'For secure rooms or areas (*containing inspectable SIPRNet assets) check windows as follows: 

1. Window placement in secure rooms should be minimal.  Ideally, there should be no large or entirely glass walls; although this will not automatically result in a finding if the glass is hardened to the same degree as the contiguous walls and properly obscured from outside viewing. Where windows are located on the exterior of secure rooms (AKA: collateral classified open storage areas) the vulnerabilities, existing and potential additional countermeasures, and residual risk associated with the windows must be considered in an assessment of risk for the secure room. NOTE that a risk assessment is required for all secure rooms IAW DoD Manual 5200.01, Volume 3, Enclosure 3, paragraph 4.   

2.  Windows that are less than 18 feet above the ground measured from the bottom of the window, or are easily accessible by means of objects directly beneath the windows shall be constructed from or covered with materials that provide protection from forced entry. The protection provided to the windows need be no stronger than the strength of the contiguous walls.  Hurricane rated windows, ballistic proof windows, non-opening double or triple pane windows, etc. should be considered acceptable as equivalent to contiguous walls.  Welded steel bars attached to the structure surrounding the window may also be used for hardening windows that are not as strong as the contiguous walls (e.g. single pane glass).  

3.  As an alternative to hardening windows (that are not as strong as the contiguous walls) with welded steel bars; secure rooms that are located within an access controlled installation or compound may eliminate the requirement for forced entry protection if the following countermeasures are taken:   All windows within 18 feet of ground level, that are capable of being opened from inside the protected space shall make the windows inoperable either by permanently sealing them or equipping them on the inside with a locking mechanism and also protecting them by an IDS, either independently (e.g. glass break sensors) or by motion detection sensors in the space.  

4. Windows will be covered with curtains, screens or otherwise limit visibility into the secure room space when classified equipment, documents or media can be viewed from outside the area.
                       
TACTICAL ENVIRONMENT:  This check is applicable where secure rooms are used to protect classified materials or systems.  The only exception will be for urgent (short term) tactical operations or other contingency situations where fixed facilities and equipment are not yet present or incapable of being used.'
  desc 'fix', 'For secure rooms or areas (*containing inspectable SIPRNet assets) the following standards must be used: 

1. Window placement in secure rooms must be minimal. There must be no large or entirely glass walls.  Where windows are located on the exterior of secure rooms (AKA: collateral classified open storage areas) the vulnerabilities, existing and potential additional countermeasures, and residual risk associated with the windows must be considered in an assessment of risk for the secure room. NOTE that a risk assessment is required for all secure rooms IAW DoD Manual 5200.01, Volume 3, Enclosure 3, paragraph 4.   

2.  Windows that are less than 18 feet above the ground measured from the bottom of the window, or are easily accessible by means of objects directly beneath the windows shall be constructed from or covered with materials that provide protection from forced entry. The protection provided to the windows need be no stronger than the strength of the contiguous walls.  Hurricane rated windows, ballistic proof windows, non-opening double or triple pane windows, etc. should be considered acceptable as equivalent to contiguous walls.  Welded steel bars attached to the structure surrounding the window may also be used for hardening windows that are not as strong as the contiguous walls (e.g. single pane glass).  

3.  As an alternative to hardening windows (that are not as strong as the contiguous walls) with welded steel bars; secure rooms that are located within an access controlled installation or compound may eliminate the requirement for forced entry protection if the following countermeasures are taken:   All windows within 18 feet of ground level, that are capable of being opened from inside the protected space shall make the windows inoperable either by permanently sealing them or equipping them on the inside with a locking mechanism and also protecting them by an IDS, either independently (e.g. glass break sensors) or by motion detection sensors in the space.

4. Windows will be covered with curtains, screens or otherwise limit visibility into the secure room space when classified equipment, documents or media can be viewed from outside the area.'
  impact 0.7
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49230r770057_chk'
  tag severity: 'high'
  tag gid: 'V-245799'
  tag rid: 'SV-245799r770306_rule'
  tag stig_id: 'IS-02.01.05'
  tag gtitle: 'IS-02.01.05'
  tag fix_id: 'F-49185r770058_fix'
  tag 'documentable'
  tag legacy: ['SV-41539r3_rule', 'V-31272']
end
