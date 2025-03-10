control 'SV-245809' do
  title 'Vault/Secure Room Storage Standards - Automated Entry Control System (AECS) and Intrusion Detection System (IDS) Head-End Equipment Protection:  The physical location (room or area) containing AECS and IDS head-end equipment (server and/or work station/monitoring equipment) where authorization, personal identification or verification data is input, stored, or recorded and/or where system status/alarms are monitored must be physically protected.'
  desc 'Inadequate physical protection of Intrusion Detection System or Automated Entry Control System servers, data base storage drives, or monitoring work stations could result in unauthorized access to core system devices providing protection for classified vaults, secure rooms and collateral classified open storage areas. This could result in the loss of confidentiality, integrity or availability of system functionality or data. The impact of this would be possible undetected and unauthorized access to classified processing spaces; resulting in the loss or compromise of classified information or sensitive information such as personal data (PII) of persons issued access control cards or badges.

REFERENCES:

The Information Security Oversight Office (ISOO): http://www.archives.gov/isoo/   Implementing Directive for Protection of Classified (for Executive Order 13526), 32 CFR Parts 2001 and 2003 Classified National Security Information: paragraph 2001.43 Storage, (2) Secret.

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraphs 24.j. and 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: MP-4, PE-1, PE-2, PE-3, PE-6, PE-8 and PE-9.

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information:  Appendix to Enclosure 3, paragraphs 2.f.(2), 3.a(5). and 3.a.(6).

DoD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016, paragraphs 5-313. e. and 5-313 h.'
  desc 'check', 'Requirements Summary:

Protection must be established and maintained for all component devices or equipment that constitute the automated entry control system (AECS) and/or the intrusion detection system (IDS) used to protect a vault, secure room or collateral classified open storage area, which contains SIPRNet assets. 

In particular the physical location (room or area) containing AECS and IDS "head-end" equipment (server and/or work station/monitoring equipment) where authorization, personal identification or verification data is input, stored, or recorded and/or where system status/alarms are monitored must be protected.

CHECKS:  

Check #1. Check to ensure the physical location containing the primary IDS "head-end" equipment (server and/or work station/monitoring equipment) is in a continuously occupied location (e.g., guard monitoring station - for alarms and CCTV).  (CAT I)

Check #2. Check to ensure the continuously occupied space limits unescorted access to only those employees responsible for monitoring or controlling the IDS and/or AECS.  Automated entry control system card/badge readers or cipher locks may be used to fulfill this requirement.  (CAT II)

Check #3.  If not co-located with the IDS "head-end" equipment; check to ensure the physical location containing the primary AECS "head-end" equipment is in a continuously occupied location OR protected minimally within a room with a BMS alarm contact on each door, window or opening and with interior motion detection sensors that are activated at the end of each duty day.  (CAT II)

Check #4.  Check to ensure that AECS system card readers with coded access cards or badges (not cipher locks or keyed locks) are used to secure the doors to rooms protecting AECS "head-end" equipment that are not located within a continuously occupied location. (CAT II)

Check #5.  Check to ensure that alarms from sensors in the room protecting AECS "head-end" equipment are monitored at the primary IDS monitoring location.  (CAT II)  

Check #6.  A secondary or supplemental AECS server/workstation or IDS data/monitoring workstation might not be located in a 24/7 occupied work space.  In instances when AECS or IDS secondary head-end equipment is not continuously attended by employees responsible for monitoring or controlling it - Check to ensure it is protected minimally within a room with a BMS alarm contact on each door, window or opening and interior motion detection sensors are installed and activated at the end of each duty day.  (CAT I)

Check #7.  Check to ensure that AECS system card readers with coded access cards or badges (not cipher locks or keyed locks) are used to secure the doors to rooms protecting secondary IDS or AECS "head-end" equipment that are not located within a continuously occupied location.  (CAT II)

Check #8.  Check to ensure that alarms from sensors in the room protecting secondary IDS or AECS "head-end" equipment are monitored at the primary IDS monitoring location.  (CAT I)

Check #9.  If 4-hour checks are used in lieu of IDS for vaults, secure rooms or collateral classified open storage areas; then 4-hour checks of the room or area used to house the (secondary) IDS and/or (primary/secondary) AECS "head-end" equipment may also be used in lieu of an IDS. Check to ensure the use of 4-hour checks in lieu of IDS to protect (secondary) IDS and/or (primary/secondary) AECS "head-end" equipment is based on a documented risk assessment.  (CAT II)

Check #10.  If used, check to ensure that random checks (not to exceed 4-hours) of the room or area used to house the IDS or AECS "head-end" equipment are documented and maintained on file for a minimum of 90 days.  (CAT II)

TACTICAL ENVIRONMENT:  This check is applicable where Vaults/Secure Rooms are used to protect classified materials or systems in a tactical environment. The only exception will be for urgent (short term) tactical operations or other contingency situations where fixed facilities and equipment are not yet present or incapable of being used.'
  desc 'fix', '1. The physical location containing the primary IDS "head-end" equipment (server and/or work station/monitoring equipment) must be located in a continuously occupied location (e.g., guard monitoring station for alarms and CCTV).  

2. The continuously occupied space must limit unescorted access to only those employees responsible for monitoring or controlling the IDS and/or AECS.  Automated entry control system card/badge readers or cipher locks should be used to fulfill this requirement.  

3.  If not co-located with the IDS "head-end" equipment; the physical location containing the primary AECS "head-end" equipment must be located in a continuously occupied location OR protected minimally within a room with a BMS alarm contact on each door, window or opening and with interior motion detection sensors that are activated at the end of each duty day.  

4.  AECS system card readers with coded access cards or badges (not cipher locks or keyed locks) must be used to secure the doors to rooms protecting AECS "head-end" equipment that are not located within a continuously occupied location. 

5.  Alarms from sensors in the room protecting AECS "head-end" equipment must be monitored at the primary IDS monitoring location.    

6.  A secondary or supplemental AECS server/workstation or IDS data/monitoring workstation might not be located in a 24/7 occupied work space.  In instances when AECS or IDS secondary head-end equipment is not continuously attended by employees responsible for monitoring or controlling it - it must be protected minimally within a room with a BMS alarm contact on each door, window or opening and interior motion detection sensors are installed and activated at the end of each duty day.  

7.  AECS system card readers with coded access cards or badges (not cipher locks or keyed locks) must be used to secure the doors to rooms protecting secondary IDS or AECS "head-end" equipment that are not located within a continuously occupied location.  

8.  Alarms from sensors in the room protecting secondary IDS or AECS "head-end" equipment must be monitored at the primary IDS monitoring location.  

9.  If 4-hour checks are used in lieu of IDS for vaults, secure rooms or collateral classified open storage areas; then 4-hour checks of the room or area used to house the (secondary) IDS and/or (primary/secondary) ACS "head-end" equipment may also be used. The use of 4-hour checks in lieu of IDS to protect (secondary) IDS and/or (primary/secondary) AECS "head-end" equipment must be based on a documented risk assessment.  

10.  If used, random checks (not to exceed 4-hours) of the room or area used to house the IDS or AECS "head-end" equipment must be documented and maintained on file for a minimum of 90 days.'
  impact 0.7
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49240r822863_chk'
  tag severity: 'high'
  tag gid: 'V-245809'
  tag rid: 'SV-245809r822865_rule'
  tag stig_id: 'IS-02.01.15'
  tag gtitle: 'IS-02.01.15'
  tag fix_id: 'F-49195r822864_fix'
  tag 'documentable'
  tag legacy: ['SV-41832r3_rule', 'V-31549']
end
