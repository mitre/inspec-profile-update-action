control 'SV-43876' do
  title 'Protected Distribution System (PDS) Construction - Alarmed Carrier'
  desc 'A PDS that is not constructed and configured as required could result in the covert or undetected interception of classified information.  An Alarmed Carrier is one of five types of Category 2 PDS.  It is the most suitable alternative to Hardened and Continuously Viewed PDS (internal facility PDS options), when the unencrypted data transmission line is concealed above suspended ceilings, below raised floors, between walls or in any situation where the line is not visible for inspection.  In lieu of daily visual inspections the functionality of the PDS alarm must be tested at least weekly - as based on guidance in the CNSSI 7003.

REFERENCES:
                            
CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 35.c.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016 Chapter 5, Section 4, paragraphs 5-402.c., 5-403 and Section 9 

DoD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DoD Information Security Program: Protection of Classified Information:   
Encl 4, para 3.b. and 4.a.; Appendix to Encl 3, para 2 & 2.f.(2); 
                                    
DoD Manual 5200.02 Procedures for the DoD Personnel Security Program (PSP), 3 April 2017 
                                                      
NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls:  PE-4, PE-6(1), (2) & (3), SC-7, and SC-8

CNSSI No.7003, September 2015, Protected Distribution Systems (PDS), Section IV, paragraph 7. and Section X, paragraph 30.d.'
  desc 'check', 'An Alarmed PDS is one of five types of Category 2 PDS IAW the CNSSI 7003. It is a suitable alternative for the two types of interior PDS, which are Hardened Carrier or Continuously Viewed Carrier. It should be used when the unencrypted data transmission line is concealed above suspended ceilings, below raised floors, between walls or in any situation where the line is not visible for inspection.  In lieu of daily visual inspections the functionality of the PDS alarm must be tested at least weekly - or as based on guidance in the CNSSI 7003.

Use this set of checks where the unencrypted SIPRNet cable must be installed in a PDS and the site indicates it is an alarmed PDS.

Check to ensure SIPRNet data cables are installed in a carrier properly configured as an "Alarmed Carrier" IAW the following guidelines:
 
1. Ideally the carrier will be constructed of solid electrical metallic tubing (EMT), ferrous conduit or pipe, or rigid-sheet steel ducting, utilizing elbows, couplings, nipples, and connectors of the same material. Connectors need not be permanently sealed in an alarmed carrier.  As a minimum the carrier may consist of any material equal to or better than standards for a "Simple PDS" (e.g., wood, PVT, EMT, ferrous conduit.  The key to determining the appropriateness of a PDS carrier is its suitability for supporting the functionality of the approved alarm sensor, which provides a means to detect tampering and/or breach of the actual PDS carrier - *not a breach of the space surrounding the carrier. An alarmed carrier must be protected by an alarm system that detects attempted penetration of the carrier. An IDS sensor capable of detecting changes in carrier air pressure is an example of an acceptable detection methodology. (CAT I)

2. As an alternative to an alarmed carrier, the space surrounding the entire carrier may be covered by an area or volumetric (e.g., infrared, motion detection) alarm system.  (CAT I)

3. The carrier and/or volumetric alarm system sensor employed must be approved by the cognizant physical security authorities.  Documentation must exist to support this approval. (CAT II)

4. The alarm system and signal transmission must be part of an Intrusion Detection System (IDS) meeting the requirements of the Appendix to Enclosure 3 of DoD Manual 5200.01,V3 (INFOSEC - Protection of Classified Information). For instance: The alarm must provide protection from tampering and be able to register malfunctions. The alarm system must also transmit a line fault message to the annunciator panel if the system fails. (CAT I)

5. The alarm signal must be sent to a 24/7 monitor station that is supervised continuously by U.S. citizens who have been subjected to a trustworthiness determination according to DoD Manual 5200.02 Procedures for the DoD Personnel Security Program (PSP). (CAT I)

6. The monitor station must be capable of notifying security forces that can respond within 15 minutes. (CAT I)

*NOTE: May be reduced to a CAT II severity level finding if the monitor station is capable of notifying security forces but the security forces are not capable of responding within 15 minutes.

7. PDS alarm functionality and performance must be verified on at least a weekly basis IAW Table 5 of the CNSSI 7003. (CAT I)
 
*NOTE: Alarm functionality tests performed less than weekly, but at least once every 3-months can be reduced to a CAT II severity level finding.

8. A Standard Operating Procedure (SOP) must be available, which is approved by the facility security officer or security manager and commander/director, and the PDS approval authority. (CAT III)
  
This SOP must include procedures to:

a. Verify the alarm functionality and performance on at least a weekly basis IAW Table 5 of the CNSSI 7003.
 
b. Ensure response by security personnel in the area of possible attempted penetration, within 15 minutes of discovery; 
 
c. Provide for inspection of the PDS to determine the cause of the alarm;

d. Define action to be taken regarding the termination of transmission;

e. Initiate investigation of actual intrusion attempt, etc.

9. The PDS is not located within an Uncontrolled Access Area (UAA) and National Manager (NSA) approved encryption solutions must be employed.  (CAT I)'
  desc 'fix', 'An Alarmed PDS is one of five types of Category 2 PDS IAW the CNSSI 7003. It is a suitable alternative for the two types of interior PDS, which are Hardened Carrier or Continuously Viewed Carrier. It should be used when the unencrypted data transmission line is concealed above suspended ceilings, below raised floors, between walls or in any situation where the line is not visible for inspection.  In lieu of daily visual inspections the functionality of the PDS alarm must be tested at least weekly - or as based on guidance in the CNSSI 7003.

Ensure unencrypted SIPRNet data cables are installed in a carrier properly configured as an "Alarmed Carrier" IAW the following guidelines: 

1. Ideally the carrier will be constructed of solid electrical metallic tubing (EMT), ferrous conduit or pipe, or rigid-sheet steel ducting, utilizing elbows, couplings, nipples, and connectors of the same material. Connectors need not be permanently sealed in an alarmed carrier.  As a minimum the carrier may consist of any material equal to or better than standards for a "Simple PDS" (e.g., wood, PVT, EMT, ferrous conduit.  The key to determining the appropriateness of a PDS carrier is its suitability for supporting the functionality of the approved alarm sensor, which provides a means to detect tampering and/or breach of the actual PDS carrier - *not a breach of the space surrounding the carrier.  An IDS sensor capable of detecting changes in carrier air pressure is an example of an acceptable detection methodology.

2. As an alternative to an alarmed carrier, the space surrounding the entire carrier may be covered by an area or volumetric (e.g., infrared, motion detection) alarm system.
 
3. The carrier and/or volumetric alarm system sensor employed must be approved by the cognizant physical security authorities.  Documentation must exist to support this approval.
 
4. The alarm system and signal transmission must be part of an Intrusion Detection System (IDS) meeting the requirements of the Appendix to Enclosure 3 of DoD Manual 5200.01, V3 (INFOSEC - Protection of Classified Information). For instance: The alarm must provide protection from tampering and be able to register malfunctions. The alarm system must also transmit a line fault message to the annunciator panel if the system fails.
 
5. The alarm signal must be sent to a 24/7 monitor station that is supervised continuously by U.S. citizens who have been subjected to a trustworthiness determination according to DoD Manual 5200.02 Procedures for the DoD Personnel Security Program (PSP).
 
6. The monitor station must be capable of notifying security forces that can respond within 15 minutes.
 
7. PDS alarm functionality and performance must be verified on at least a weekly basis IAW Table 5 of the CNSSI 7003.
 
8. A Standard Operating Procedure (SOP) must be available, which is approved by the facility security officer or security manager and commander/director, and the PDS approval authority. 
 
This SOP must include procedures to:

a. Verify the alarm functionality and performance on at least a weekly basis IAW Table 5 of the CNSSI 7003.
 
b. Ensure response by security personnel in the area of possible attempted penetration, within 15 minutes of discovery; 
 
c. Provide for inspection of the PDS to determine the cause of the alarm;

d. Define action to be taken regarding the termination of transmission;

e. Initiate investigation of actual intrusion attempt, etc.

9. The PDS must not be located within an Uncontrolled Access Area (UAA) and National Manager (NSA) approved encryption solutions must be employed.'
  impact 0.7
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-41605r32_chk'
  tag severity: 'high'
  tag gid: 'V-33456'
  tag rid: 'SV-43876r3_rule'
  tag stig_id: 'CS-04.01.08'
  tag gtitle: 'PDS Construction - Alarmed Carrier'
  tag fix_id: 'F-37378r9_fix'
  tag 'documentable'
  tag severity_override_guidance: 'The default is a Category I severity level when the physical make-up of the alarmed PDS is found to be inadequate, non-functional or otherwise vulnerable to undetected intrusion.  Not conducting any checks of the PDS alarm functionality will also result in a CAT I finding.  Alarms not continuously monitored by properly cleared US Personnel at a 24/7 monitoring location will also result in a CAT I finding.

If the alarmed PDS is located within an Uncontrolled Access Area (UAA) and/or National Manager (NSA) approved encryption solutions are not employed a CAT I finding will result.

May be reduced to CAT II if the PDS alarm system functions properly and checks of the alarm system are conducted at a frequency less than on a weekly basis. 

Checks must be conduct at least every 3-months or a CAT I severity level must be applied.
 
May be reduced to a CAT II if the PDS alarm functions properly and checks of the alarm system are conducted on a weekly basis and the monitor station is capable of notifying security forces but the security forces are not capable of responding within 15 minutes.
 
May be reduced to a CAT II if the PDS alarm functions properly and checks of the alarm system are conducted on a weekly basis but the alarm system sensor employed is not approved by the cognizant COMSEC and/or physical security authorities and/or documentation does not exist to support this approval. 

May be reduced to a CAT III if the PDS alarm functions properly and checks of the alarm system are conducted on at least a weekly basis but there is no SOP detailing actions for checking the system functionality or response to alarms.'
  tag potential_impacts: 'There are five types of PDS classified as Category 2 Distribution Systems using one of the following carriers: hardened, buried, suspended, alarmed, or continuously viewed. 
 
This requirement (Alarmed Carrier, STIG ID CS-04.01.08) may be used as an alternative Category 2 carrier in lieu of the following two types of distribution systems: (Hardened STIG ID: CS-04.01.02 and Continuously Viewed STIG ID: CS-04.01.06).  An alarmed carrier is not a suitable alternative to either buried or suspended (external) PDS.  If an alarmed carrier is used the requirements for hardened and continuously viewed carriers are NA.'
end
