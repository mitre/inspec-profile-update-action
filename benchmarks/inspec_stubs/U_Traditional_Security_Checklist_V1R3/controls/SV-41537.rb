control 'SV-41537' do
  title 'Information Security (INFOSEC) - Secure Room Storage Standards  Wall and Ceiling Structural Integrity (AKA: True Floor to True Ceiling Connection)'
  desc 'Failure to meet standards for ensuring that there is structural integrity of the physical perimeter surrounding a secure room (AKA: collateral classified open storage area) IAW DoD Manual 5200.01, Volume 3, Enclosure 3 could result in the undetected loss or compromise of classified material.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraphs 24.j.and 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
MP-4, PE-3 and PE-5

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information: Appendix to Encl 3, para 1.b.(1).

Information Security Oversight Office, 32 CFR Parts 2001 and 2003 Classified National Security Information: paragraph 2001.53 Open storage areas, (a) Construction.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 5, Section 8, Construction Requirements.'
  desc 'check', 'For secure rooms or areas (*containing inspectable SIPRNet assets) check walls are true floor to true ceiling.  Walls shall be extended to the true ceiling and attached with permanent construction materials.  As an alternative true walls and true ceilings can be connected with steel mesh or 18-gauge expanded steel screen. Likewise, walls below raised floor (computer room) space may be connected to the true floor with steel mesh or 18-gauge expanded steel screen.        

TACTICAL ENVIRONMENT: This check is applicable where secure rooms are used to protect classified materials or systems.  The only exception will be for urgent (short term) tactical operations or other contingency situations where fixed facilities and equipment are not yet present or incapable of being used.'
  desc 'fix', '1. For secure rooms or areas (*containing inspectable SIPRNet assets) walls must be true floor to true ceiling. 

2. Walls shall be extended to the true ceiling and attached with permanent construction materials. 

3. As an alternative true walls and true ceilings can be connected with steel mesh or 18-gauge expanded steel screen. 

4. Likewise, walls below raised floor (computer room) space may be connected to the true floor with steel mesh or 18-gauge expanded steel screen.'
  impact 0.7
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-40002r5_chk'
  tag severity: 'high'
  tag gid: 'V-31270'
  tag rid: 'SV-41537r3_rule'
  tag stig_id: 'IS-02.01.03'
  tag gtitle: 'Information Security (INFOSEC) - Secure Room Standards  Wall  Ceiling Integrity'
  tag fix_id: 'F-35167r7_fix'
  tag 'documentable'
end
