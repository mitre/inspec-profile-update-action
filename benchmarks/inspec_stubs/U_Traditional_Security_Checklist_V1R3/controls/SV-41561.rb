control 'SV-41561' do
  title 'Vault/Secure Room Storage Standards - Intrusion Detection System (IDS) / Automated Entry Control System (AECS) Primary and Emergency Power Supply'
  desc 'Failure to meet standards for ensuring that there is an adequate commercial and back-up power sources for IDS/AECS with uninterrupted failover to emergency power could result in a malfunctionof the physical alarm and access control system.  This could result in the undetected breach of classified open storage / secure rooms or vaults containing SIPRNet assets and undetected loss or compromise of classified material.

REFERENCES:

The Information Security Oversight Office (ISOO): http://www.archives.gov/isoo/   Implementing Directive for Protection of Classified (for Executive Order 13526), 32 CFR Parts 2001 and 2003 Classified National Security Information: paragraph 2001.43 Storage, (2) Secret.

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: MP-4, PE-3, PE-5, PE-6(1)

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information:  Appendix to Enclosure 3, paragraphs 2.d.(7)(a) and (b).

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 5, Section 9. Intrusion Detection Systems.'
  desc 'check', "Primary Power Checks:

Check #1. Check to ensure primary power for all Intrusion Detection System (IDS) equipment and Automated Entry Control system (AECS) equipment is either commercial AC or DC power. 

Check #2. Check to ensure that in the event of commercial power failure at either the secure room/area or monitor station, the equipment changes power sources without causing an intrusion alarm indication. An Uninterrupted Power Supply (UPS) will be required for this to occur.   

Emergency (Backup) Power Checks:

Check #1. Check to ensure that emergency power consists of a protected independent backup power source that provides a minimum of 8-hours operating battery and/or generator power. When batteries are used for emergency power, they shall be maintained at full charge by automatic charging circuits. The manufacturer's periodic maintenance schedule shall be followed and results documented.

Check #2.  Power Source and Failure Indication:  Check to ensure that an illuminated indication exists at the Power Control Unit (PCU) of the power source in use (AC or DC).  

Check #3. Check to ensure equipment at the IDS/AECS monitor station indicates a failure in power source, a change in power source, and the location of the failure or change.                                          

TACTICAL ENVIRONMENT:  This check is applicable where Vaults/Secure Rooms are used to protect classified materials or systems in a tactical environment. The only exception will be for urgent (short term) tactical operations or other contingency situations where fixed facilities and equipment are not yet present or incapable of being used."
  desc 'fix', "Fixes - Primary Power:

Fix #1. Ensure primary power for all Intrusion Detection System (IDS) equipment and Automated Entry Control system (AECS) equipment is either commercial AC or DC power. 

Fix #2. Ensure that in the event of commercial power failure at either the secure room/area or monitor station, the equipment changes power sources without causing an intrusion alarm indication. An Uninterrupted Power Supply (UPS) will be required for this to occur.   

Fixes - Emergency (Backup) Power:

Fix #1. Ensure that emergency power consists of a protected independent backup power source that provides a minimum of 8-hours operating battery and/or generator power. When batteries are used for emergency power, they shall be maintained at full charge by automatic charging circuits. The manufacturer's periodic maintenance schedule shall be followed and results documented.

Fix #2.  Power Source and Failure Indication:  Ensure that an illuminated indication exists at the Power Control Unit (PCU) of the power source in use (AC or DC).  

Fix #3. Ensure equipment at the IDS/AECS monitor station indicates a failure in power source, a change in power source, and the location of the failure or change."
  impact 0.5
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-40052r7_chk'
  tag severity: 'medium'
  tag gid: 'V-31290'
  tag rid: 'SV-41561r3_rule'
  tag stig_id: 'IS-02.02.05'
  tag gtitle: 'Vault/Secure Room Standards - IDS/AECS Power Supply'
  tag fix_id: 'F-35209r5_fix'
  tag 'documentable'
end
