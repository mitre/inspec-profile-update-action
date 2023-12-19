control 'SV-245798' do
  title 'Information Security (INFOSEC) - Vault/Secure Room Storage Standards - Openings in Perimeter Exceeding 96 Square Inches'
  desc 'Failure to meet standards for ensuring that there is structural integrity of the physical perimeter surrounding a vault or secure room (AKA: collateral classified open storage area) IAW DoD Manual 5200.01, Volume 3, Enclosure 3 could result in the undetected loss or compromise of classified material.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraphs 24.j. and 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
MP-4, PE-3 and PE-5

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information: Appendix to Encl 3, para 1.b.(5).

Information Security Oversight Office, 32 CFR Parts 2001 and 2003 Classified National Security Information: paragraph 2001.53 Open storage areas, (c) Vents, ducts, and miscellaneous openings.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 5, Section 8, Construction Requirements, paragraph 5-801.h. Miscellaneous Openings.'
  desc 'check', 'For vaults, secure rooms or areas (*containing inspectable SIPRNet assets): Utility openings such as ducts and vents and any holes or passages through the secure room perimeter will be kept at less than a man-passable (96 square inches) opening. Openings larger than 96 square inches will be hardened in accordance with Military Handbook 1013/1A.

TACTICAL ENVIRONMENT:  This check is applicable where secure rooms are used to protect classified materials or systems.  The only exception will be for urgent (short term) tactical operations or other contingency situations where fixed facilities and equipment are not yet present or incapable of being used.'
  desc 'fix', 'For vaults, secure rooms or areas (*containing inspectable SIPRNet assets): Utility openings such as ducts and vents and any holes or passages through the secure room perimeter must be kept at less than a man-passable (96 square inches) opening. Openings larger than 96 square inches will be hardened in accordance with Military Handbook 1013/1A.'
  impact 0.7
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49229r770054_chk'
  tag severity: 'high'
  tag gid: 'V-245798'
  tag rid: 'SV-245798r770305_rule'
  tag stig_id: 'IS-02.01.04'
  tag gtitle: 'IS-02.01.04'
  tag fix_id: 'F-49184r770055_fix'
  tag 'documentable'
  tag legacy: ['SV-41538r3_rule', 'V-31271']
end
