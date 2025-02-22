control 'SV-245815' do
  title 'Vault/Secure Room Storage Standards - Intrusion Detection System and Automated Entry Control System (IDS/AECS) Component Tamper Protection'
  desc 'Failure to tamper protect IDS/AECS component enclosures and access points external to protected vaults/secure rooms space could result in the undetected modification or disabling of IDS/AECS system components.  This could lead to the undetected breach of secure space containing SIPRNet assets and result in the undetected loss or compromise of classified information or materials.

REFERENCES:

The Information Security Oversight Office (ISOO): http://www.archives.gov/isoo/   Implementing Directive for Protection of Classified (for Executive Order 13526), 32 CFR Parts 2001 and 2003 Classified National Security Information: paragraph 2001.43 Storage, (2) Secret.

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: MP-4, PE-3, PE-5, PE-6(1)

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information:  Appendix to Enclosure 3, paragraphs 2.d.(8 and 3.a.(5)(b).

DoD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 5, Section 9. Intrusion Detection Systems and Section 3. AECS paragraph 5-313.f.'
  desc 'check', 'Requirements Summary:

Protection must be established and maintained for all component devices or equipment that constitute the Automated Entry Control System (AECS) and/or the Intrusion Detection System (IDS) used to protect a vault, secure room or collateral classified open storage area, which contains SIPRNet assets.

If access to a junction box or controller will enable an unauthorized modification, then alarmed tamper protection, which is normally provided by a pressure sensitive switch must be used.  

CHECKS:

1.  Check to ensure that IDS/AECS components located both outside and inside the secure area have tamper protection resulting in an alarm signal sent to the primary IDS Monitoring Station.  Normally this is provided by a pressure sensitive switch, which automatically sends an alarm signal when the protective enclosure covering component equipment is opened. 

2.  Check to ensure that ALL IDS/AECS ancillary equipment such as card readers, keypads, communication or interface devices for vaults, secure rooms, or collateral classified open storage areas containing SIPRNet assets  have tamper resistant enclosures and are securely fastened to the wall or other permanent structure.  Control panels and AECS devices located within a Secret or TS Controlled Access Area (CAA) need only a minimal degree of physical security protection sufficient to preclude unauthorized access to the mechanism. 
                        
TACTICAL ENVIRONMENT:  This check is applicable where Vaults/Secure Rooms are used to protect classified materials or systems in a tactical environment. The only exception will be for urgent (short term) tactical operations or other contingency situations where fixed facilities and equipment are not yet present or incapable of being used.'
  desc 'fix', 'Requirements Summary:

Protection must be established and maintained for all component devices or equipment that constitute the Automated Entry Control System (AECS) and/or the Intrusion Detection System (IDS) used to protect a vault, secure room or collateral classified open storage area, which contains SIPRNet assets.

If access to a junction box or controller will enable an unauthorized modification, then alarmed tamper protection, which is normally provided by a pressure sensitive switch must be used.  

Fixes:

1.  IDS/AECS components located both outside and inside the secure area must have tamper protection resulting in an alarm signal sent to the primary IDS Monitoring Station.  Normally this is provided by a pressure sensitive switch, which automatically sends an alarm signal when the protective enclosure covering component equipment is opened. 

2. ALL IDS/AECS ancillary equipment such as card readers, keypads, communication or interface devices for vaults, secure rooms, or collateral classified open storage areas containing SIPRNet assets must have tamper resistant enclosures and be securely fastened to the wall or other permanent structure.  Control panels and AECS devices located within a Secret or TS Controlled Access Area (CAA) need only a minimal degree of physical security protection sufficient to preclude unauthorized access to the mechanism.'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49246r770105_chk'
  tag severity: 'medium'
  tag gid: 'V-245815'
  tag rid: 'SV-245815r822872_rule'
  tag stig_id: 'IS-02.02.06'
  tag gtitle: 'IS-02.02.06'
  tag fix_id: 'F-49201r770106_fix'
  tag 'documentable'
  tag legacy: ['V-31291', 'SV-41562r3_rule']
end
