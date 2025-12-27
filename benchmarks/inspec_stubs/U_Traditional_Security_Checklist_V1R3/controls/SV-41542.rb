control 'SV-41542' do
  title 'Information Security (INFOSEC) - Secure Room Storage Standards - Balanced Magnetic Switch (BMS) on Perimeter Doors'
  desc 'Failure to meet standards for ensuring that there is structural integrity of the physical perimeter surrounding a secure room (AKA: collateral classified open storage area) IAW DoD Manual 5200.01, Volume 3 could result in the undetected loss or compromise of classified material.  When a physical Intrusion Detection System (IDS) is used as the supplemental protection measure (in lieu of 4-hour random checks) for secure rooms there is a requirement to place a Balanced Magnetic Switch (BMS) alarm contact on the primary ingress/egress door and any secondary/emergency exit doors.  This alarm sensor is an essential part of any properly installed IDS and ensures that doors opened by force or that are left open are immediately detected.  A BMS (AKA: triple biased alarm contact) is the most difficult door alarm contact to defeat and must be used in lieu of dual biased or simple alarm contacts.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraphs 24.j.and 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
MP-4, PE-3, PE-5 and PE-6

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information: Appendix to Enclosure 3, paragraph 2.e.(4).

The Information Security Oversight Office (ISOO): http://www.archives.gov/isoo/   Implementing Directive for Protection of Classified (for Executive Order 13526), 32 CFR Parts 2001 and 2003 Classified National Security Information: paragraph 2001.43 Storage, (2) Secret.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 5, Section 9. Intrusion Detection Systems.'
  desc 'check', 'Where an IDS is used in lieu of 4-hour random checks, for secure rooms or collateral classified open storage areas containing SIPRNet assets, each perimeter door (primary and secondary) shall be protected by a balanced magnetic switch (BMS) that meets the standards of UL 634.  

NOTE:  Ensure the alarm contact is an actual BMS, which is defined as a "Triple Biased" alarm contact.  Introduction of a foreign magnet by an intruder in an attempt to defeat the BMS will result in an alarm being sent.  

If used, Simple and Dual Biased contacts are not BMS and will result in a CAT II finding.  

No alarm contacts on all doors is a CAT I finding.
                             
TACTICAL ENVIRONMENT:  This check is applicable where Secure Rooms are used to protect classified materials or systems in a tactical environment. The only exception will be for urgent (short term) tactical operations or other contingency situations where fixed facilities and equipment are not yet present or incapable of being used.'
  desc 'fix', 'Where an IDS is used in lieu of 4-hour random checks, for secure rooms or collateral classified open storage areas containing SIPRNet assets, each perimeter door (primary and secondary) must be protected by a balanced magnetic switch (BMS) that meets the standards of UL 634. 

NOTE: The alarm contact must be an actual BMS, which is defined as a "Triple Biased" alarm contact. Introduction of a foreign magnet by an intruder in an attempt to defeat the BMS will result in an alarm being sent. Simple and Dual Biased contacts are not BMS and will result in a finding.'
  impact 0.7
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-40017r5_chk'
  tag severity: 'high'
  tag gid: 'V-31275'
  tag rid: 'SV-41542r3_rule'
  tag stig_id: 'IS-02.01.08'
  tag gtitle: 'Information Security (INFOSEC) - Secure Room Standards - BMS on Perimeter Doors'
  tag fix_id: 'F-35186r3_fix'
  tag 'documentable'
  tag severity_override_guidance: 'Default severity level is a CAT I:  Secure Rooms containing SIPRNet assets that use an  Intrusion Detection System (IDS) do not have all doors (primary and secondary) monitored with an alarm contact.
              
Reduction to CAT II: Secure Rooms containing SIPRNet assets using an IDS have all doors monitored with alarm contacts; however, the alarm contacts are not Balanced Magnetic Switches (BMS) meeting UL Standard 634.

This particular requirement for BMS (IS-02.01.08) can only be used when the IDS requirement (IS-02.01.07) is the supplemental control selected for secure rooms.  It is not applicable (NA) if the requirement for 4-hour random checks (IS-02.01.10) is used in lieu of IS-02.01.07.'
end
