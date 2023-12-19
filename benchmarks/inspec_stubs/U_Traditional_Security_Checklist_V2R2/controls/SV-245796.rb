control 'SV-245796' do
  title 'Information Security (INFOSEC) - Secure Room Storage Standards - Door Construction'
  desc 'Failure to meet construction standards could result in the undetected loss or compromise of classified material.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Encl A, paragraph 7.f.; Encl C, paragraph 10.a., and 10.b.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
MP-4, PE-3 and PE-5

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information: Encl 3, para 1.b, 14.b. and Appendix to Encl 3, para 1.b.(3), 2.e.(4) and Glossary page 122, vault definition.

Information Security Oversight Office, 32 CFR Parts 2001 and 2003 Classified National Security Information: paragraph 2001.53 Open storage areas, (b) Doors.

DoD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 5, Section 8, Construction Requirements.'
  desc 'check', 'Check all secure room doors (*containing inspectable SIPRNet assets) as follows:  

1. The doors to the room (primary and secondary) shall be substantially constructed of wood or metal. (CAT II) 

2. The hinge pins of outswing doors shall be peened, brazed, or spot welded to prevent removal. Certain hinge pins are made with internal locking pins or locking flanges and are acceptable if they cannot be removed. (CAT I)     

3. Secondary (emergency exit only) doors shall have all external hardware removed to prevent opening from outside the secure room. (CAT I)  

4. Secondary doors (doors other than those secured with locks meeting FF-L-2740) shall be secured from the inside with deadbolt emergency egress hardware, a deadbolt, or a rigid wood or metal bar that extends across the width of the door. These deadbolt locks shall be secured when the combination lock on the primary door is spun. (CAT I)

TACTICAL ENVIRONMENT: This check is applicable where  secure rooms are used to protect classified materials or systems.  The only exception will be for urgent (short term) tactical operations or other contingency situations where fixed facilities and equipment are not yet present or incapable of being used.'
  desc 'fix', 'All secure room doors (*containing inspectable SIPRNet assets) must meet the following standards: 

1. The doors to the room (primary and secondary) shall be substantially constructed of wood or metal. 

2. The hinge pins of outswing doors shall be peened, brazed, or spot welded to prevent removal. Certain hinge pins are made with internal locking pins or locking flanges and are acceptable if they cannot be removed. 

3. Secondary (emergency exit only) doors shall have all external hardware removed to prevent opening from outside the secure room. 

4. Secondary doors (doors other than those secured with locks meeting FF-L-2740) shall be secured from the inside with deadbolt emergency egress hardware, a deadbolt, or a rigid wood or metal bar that extends across the width of the door. These deadbolt locks shall be secured when the combination lock on the primary door is spun.'
  impact 0.7
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49227r770048_chk'
  tag severity: 'high'
  tag gid: 'V-245796'
  tag rid: 'SV-245796r822846_rule'
  tag stig_id: 'IS-02.01.02'
  tag gtitle: 'IS-02.01.02'
  tag fix_id: 'F-49182r770049_fix'
  tag 'documentable'
  tag legacy: ['V-31268', 'SV-41531r3_rule']
end
