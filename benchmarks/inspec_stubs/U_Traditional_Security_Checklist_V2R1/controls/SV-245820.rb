control 'SV-245820' do
  title 'Information Security (INFOSEC) - Secure Room Storage Standards - Perimeter Construction using Proper Permanent Construction Materials for True Ceiling, Walls and Floors.'
  desc 'Failure to meet standards for ensuring that there is structural integrity of the physical Perimeter surrounding a secure room (AKA: collateral classified open storage area) could result in a lack of structural integrity and the undetected loss or compromise of classified material.  Permanent construction materials; while not impenetrable, provide physical evidence of an attempted or actual intrusion into a secure room space.  Construction materials and application techniques that are not permanent in nature can  potentially be removed to allow for access to secure room space and then replaced by an intruder upon egress from the area.  This effectively negates the detection capability afforded by permanent construction techniques and materials.  Examples of non-permanent material would be modular walls that can be removed and replaced with ease or plywood board (or other materials) applied with screws or nails that can be removed from outside the secure room space and then replaced using common tools.

REFERENCES:

The Information Security Oversight Office (ISOO): http://www.archives.gov/isoo/   Implementing Directive for Protection of Classified (for Executive Order 13526), 32 CFR Parts 2001 and 2003 Classified National Security Information: paragraph 2001.53 Open storage areas.

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: MP-3, PE-3, PE-4, and PE-5.

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information:  Enclosure 3, paragraphs 3.a.(3) and 3.b.(1), (2) &(3);  Appendix to Enclosure 3, paragraph 1.b.(1), (2) & (5).

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 5, Section 8,  paragraph 5-801. b. Walls, f. Ceilings, g. Unusual Ceilings, & h. Openings.'
  desc 'check', 'For secure rooms or areas (*containing inspectable SIPRNet assets) check:

1. That walls, floor, and roof construction of secure rooms are made of permanent construction materials; i.e., plaster, gypsum wallboard, metal panels, hardboard, wood, plywood, or other materials offering resistance to, and evidence of unauthorized entry into the area. Materials such as plywood must be attached in a manner so as not to enable easy removal of screws or nails to gain ingress and then replace upon egress. 

2. The "True" ceiling shall be constructed of plaster, gypsum, wallboard material, hardware or any other acceptable material. 

TACTICAL ENVIRONMENT:  This check is applicable where vaults or secure rooms are used to protect classified materials or systems.  The only exception will be for urgent (short term) tactical operations or other contingency situations where fixed facilities and equipment are not yet present or incapable of being used.'
  desc 'fix', '1. Secure rooms or areas (*containing inspectable SIPRNet assets) must have walls, floor, and roof construction made of permanent construction materials; i.e., plaster, gypsum wallboard, metal panels, hardboard, wood, plywood, or other materials offering resistance to, and evidence of unauthorized entry into the area. 

2. Materials such as plywood must be attached in a manner so as not to enable easy removal of screws or nails to gain ingress and then replace upon egress. 

3. The "True" ceiling shall be constructed of plaster, gypsum, wallboard material, hardware or any other acceptable material.'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49251r770120_chk'
  tag severity: 'medium'
  tag gid: 'V-245820'
  tag rid: 'SV-245820r770122_rule'
  tag stig_id: 'IS-02.02.11'
  tag gtitle: 'IS-02.02.11'
  tag fix_id: 'F-49206r770121_fix'
  tag 'documentable'
  tag legacy: ['V-31269', 'SV-41535r3_rule']
end
