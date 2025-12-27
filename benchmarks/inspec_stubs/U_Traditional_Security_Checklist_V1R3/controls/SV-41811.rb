control 'SV-41811' do
  title 'Vault/Secure Room Storage Standards - Access Control During Working Hours Using Visual Control OR Automated Entry Control System (AECS) with PIN / Biometrics'
  desc 'Failure to properly monitor and control collateral classified open storage area access doors during working hours (while the FF-L-2740 combination lock is not secured)  could result in an undetected perimeter breach and limited or no capability to immediately notify response forces.  Ultimately this could result in the undetected loss or compromise of classified material.

Entrances to secure rooms or areas (and/or vaults that are opened for access) must be under visual control at all times during duty hours to prevent entry by unauthorized personnel . This may be accomplished by several methods (e.g., employee work station, guard, continuously monitored CCTV). 

An automated entry control system (AECS) may be used to control admittance during working hours instead of visual control, if it meets certain criteria * and if the room or area is continuously occupied by at least one properly cleared person.

REFERENCES:

The Information Security Oversight Office (ISOO): http://www.archives.gov/isoo/   Implementing Directive for Protection of Classified (for Executive Order 13526), 32 CFR Parts 2001 and 2003 Classified National Security Information: paragraph 2001.43 Storage, (2) Secret.

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraphs 24.j. and 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: MP-4, PE-2, PE-3, PE-5 and PE-6

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information:  Enclosure 3, paragraph 12 and Appendix to Enclosure 3, paragraphs 3.a. and 3.c.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, paragraphs 5-306, 5-312, 5-313, 5-314'
  desc 'check', %q(Background Information and Requirements Summary: 

1.  The FF-L-2740 combination lock securing the primary access door for vaults and secure rooms (AKA: collateral classified open storage areas) may be opened at the beginning of normal duty hours and left unlocked for frequent employee access only if the entrance is properly monitored and controlled.  The combination lock will be secured at the end of normal duty hours and interior motion alarms (if used) activated.  

2.  Entrances to vaults, secure rooms or collateral classified open storage areas must be under visual control at all times during duty hours to prevent entry by unauthorized personnel.

3.  An automated access control system (AECS) may be used to monitor and control admittance during working hours instead of visual control, if it consists of a swipe or proximity coded card and reader, supplemented by the use of a Personal Identification Number (PIN) or by use of Biometric readers (fingerprints, retina scanner, etc.).   Additionally, the secure room or classified storage area must be occupied by cleared employees OR under direct visual control from just outside the room or area.  Use of an Automated Entry Control System (AECS) alone may not be used to meet this standard.  Use of an AECS to control and monitor access requires the room or area be occupied by at least one properly cleared person.

4.  Visual monitoring or control of secure room access points may be accomplished by several methods (e.g., employee work station, guard, "continuously monitored" CCTV).  Employee monitoring may be conducted by cleared employees within the secure room space, who can observe all entrances or employees located just outside the secure room adjacent to an entrance may also "actively" monitor access. If CCTV is used to monitor, the CCTV cameras must cover all potential entrances and send real time images back to a continuously manned monitoring station.

5.  Regardless of the visual method used to monitor daytime access, a locking system for access control must still be used on the entrance to the secure area.  The use of automated entry control systems,(AECS with coded ID cards or badges) is encouraged.  Supplementing the coded (swipe or proximity) cards or badges with a PIN or biometrics is not required if the entrances are properly monitored by visual means.  

6.  Access to secure areas may also be controlled by electric, mechanical or electro-mechanical access control devices to limit access during duty hours, but only if the entrance is also under continuous visual control. 

7.  IMPORTANT NOTE: Electrically actuated locks (e.g., cypher, proximity card and magnetic strip card locks) do not afford by themselves the required degree of protection for classified information and must not be used as a substitute for the combination locks meeting Federal Specification FF-L-2740. 

CHECKS:

*If f visual control methods are the primary means to monitor and control access during duty hours, use the following three checks to evaluate:
 
Check #1.  Check to ensure that all possible primary or secondary entrances to vaults or secure rooms are continuously monitored by cleared employees or guards (inside or outside the room or area) or by CCTV, whenever the FF-L-2740 combination lock is disengaged for daytime or other routine access.     (CAT I)

Check #2.  Check to ensure that if CCTV is used it sends real time images to a continuously manned monitoring station.  (CAT I)

Check #3.  If CCTV is used to visually monitor the secure room or area and / or guards or other personnel are not physically controlling access: Check to ensure that access to a continuously (visually) monitored vault, secure room or collateral classified open storage area is controlled either by an Automated Entry Control System (AECS) using coded cards or badges (biometrics or PIN are not required) or by electric, mechanical or electro-mechanical access control devices to limit access during duty hours.  (CAT I)

NOTE: Electric, mechanical or electro-mechanical access control devices may not be used to control access when the entrance(s) to the vault, secure room or area are not under continuous visual monitoring either directly by cleared employees at the entrance(s) or via CCTV.  If using CCTV it must also be continuously monitored and recorded at an occupied monitoring station.

**If an Automated Entry Control System (AECS) is used to control access (without use of any authorized visual control methods), use the following seven checks to evaluate:

CHECKS:

Check#1. Check to ensure the vault, secure room or area is continuously occupied by at least one properly cleared employee during working hours (when the FF-L-2740 combination lock is not engaged. (CAT I)

Check #2. Check to ensure the AECS identifies individuals and authenticates the person's authority to enter the area through the use of a coded identification (ID) badge or card. (CAT I)

Check #3. Check to ensure that in addition to the swipe or proximity card or badge - that a personal identification number (PIN) is used.  This is required WHEN VISUAL (MONITORING) of the entrance IS NOT USED during working hours. (CAT II – when an AECS card and reader is used w/o PIN or biometrics) 

Check #4. Check the PINs are separately entered into the system by each individual using a keypad device and consist of four or more digits, randomly selected, with no known or logical association with the individuals. (CAT II –only  when an AECS with card and PIN is used) 

Check #5. Check to ensure there is a procedure to cover changing PINs when it is believed they have been compromised or subjected to compromise. (CAT III) 

Check #6. Biometrics Devices, which identify an individual requesting access by some unique personal characteristic, such as Fingerprinting, Hand Geometry, Handwriting, Retina scans, or Voice recognition may be used in conjunction with an ID badge or card in lieu of a PIN.  (CAT II – when an AECS card and reader is used w/o PIN or biometrics)

Check #7.  VERY IMPORTANT: Check to ensure that electric, mechanical or electro-mechanical access control devices such as Cipher locks ARE NOT USED to control access to vaults, secure rooms or areas when entrances  are not under continuous visual control during working hours.  Generally these locks do not provide the means for individual access codes and do not report to a central server or system monitor.  Therefore they are permissible ONLY for access control to vault, secure rooms and spaces when the entrance is under continuous visual control.  (CAT I)

TACTICAL ENVIRONMENT:  These checks are applicable where Vaults/Secure Rooms are used to protect classified materials or systems in a tactical environment. The only exception will be for urgent (short term) tactical operations or other contingency situations where fixed facilities and equipment are not yet present or incapable of being used.)
  desc 'fix', "*If use of visual control methods is the primary means to control access during duty hours, use the following three fixes to comply with requirements:

1.  All possible primary or secondary entrances to vaults or secure rooms must be continuously monitored by cleared employees or guards (inside or outside the room or area) or by CCTV, whenever the FF-L-2740 combination lock is disengaged for daytime or other routine access.     

2.  If CCTV is used it must send real time images to a continuously manned monitoring station.  

3. Access to a continuously (visually) monitored vault, secure room or collateral classified open storage area must be controlled by an Automated Entry Control System (AECS) using coded cards or badges (biometrics or PIN are not required) or by electric, mechanical or electro-mechanical access control devices to limit access during duty hours. 

**If use of an Automated Entry Control System (AECS) is used to control access (without use of any authorized visual control methods), use the following seven fixes to comply with requirements:

1.  The vault, secure room or area must be continuously occupied by at least one properly cleared employee during working hours (when the FF-L-2740 combination lock is not engaged).

2. The AECS must identify individuals and authenticate the person's authority to enter the area through the use of a coded identification (ID) badge or card. 

3. In addition to the swipe or proximity card or badge a personal identification number (PIN) must be used.  This is required WHEN VISUAL (MONITORING) CONTROLS of the entrance ARE NOT USED during working hours.  

4. The PINs must be separately entered into the system by each individual using a keypad device and consist of four or more digits, randomly selected, with no known or logical association with the individuals.
  
5. There must be a procedure in place to cover changing PINs when it is believed they have been compromised or subjected to compromise.  

6. Biometrics Devices, which identify an individual requesting access by some unique personal characteristic, such as Fingerprinting, Hand Geometry, Handwriting, Retina scans, or Voice recognition may be used in conjunction with an ID badge or card in lieu of a PIN.  

7.  VERY IMPORTANT: Electric, mechanical or electro-mechanical access control devices such as Cipher locks MUST NOT BE USED to control access to secure rooms or areas that are not under continuous visual control during working hours.  Generally these locks do not provide the means for individual access codes and do not report to a central server or system monitor.  Therefore they are permissible ONLY for access control to secure rooms and spaces when the entrance is under continuous visual control."
  impact 0.7
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-40263r28_chk'
  tag severity: 'high'
  tag gid: 'V-31529'
  tag rid: 'SV-41811r3_rule'
  tag stig_id: 'IS-02.01.14'
  tag gtitle: 'Vault/Secure Room Storage Standards - Access Control During Working Hours'
  tag fix_id: 'F-35421r13_fix'
  tag 'documentable'
  tag severity_override_guidance: 'Default severity level is a Category I (CAT I).

The severity level may be decreased to either CAT II or CAT III if the following 4- check(s) are the ONLY findings under this Rule (no findings against CAT I checks found):

Check #3. Check to ensure that in addition to the swipe or proximity card or badge - that a personal identification number (PIN) is used.  This is required WHEN VISUAL (MONITORING) of the entrance IS NOT USED during working hours. (CAT II when an AECS card and reader is used w/o PIN or biometrics) 

Check #4. Check the PINs are separately entered into the system by each individual using a keypad device and consist of four or more digits, randomly selected, with no known or logical association with the individuals. (CAT II only when an AECS with card and PIN is used) 

Check #5. Check to ensure there is a procedure to cover changing PINs when it is believed they have been compromised or subjected to compromise. (CAT III) NOTE: This check pertains only to situations where access is controlled by use of a swipe or proximity card (using an AECS card reader) along with a Personal Identity Number (PIN).

Check #6. Biometrics Devices, which identify an individual requesting access by some unique personal characteristic, such as Fingerprinting, Hand Geometry, Handwriting, Retina scans, or Voice recognition may be used in conjunction with an ID badge or card in lieu of a PIN.  (CAT II when an AECS card and reader is used w/o PIN or biometrics)'
end
