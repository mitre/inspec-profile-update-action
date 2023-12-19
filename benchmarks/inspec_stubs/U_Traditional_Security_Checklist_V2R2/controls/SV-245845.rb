control 'SV-245845' do
  title 'Controlled Unclassified Information - Handling, Storage and Controlling Access to Areas where CUI is Processed or Maintained'
  desc 'Failure to handle CUI in an approved manner can result in the loss or compromise of sensitive information.

REFERENCES:

Executive Order 13556, Controlled Unclassified Information (CUI)

The Information Security Oversight Office (ISOO): https://www.archives.gov/cui

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND); Enclosure C, paragraph 25.d.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: MP-4 and PE-3.

DoD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DoD Information Security Program: Protection of Classified Information; Enclosure 7, paragraph 13.f.

DoD Manual 5200.01, Volume 4, SUBJECT: DoD Information Security Program: Controlled Unclassified Information (CUI); Enclosure 3., paragraphs 2.e.(1), 3.d., 4.e.(3), 5.e., and Enclosure 4, paragraph 3.c.(9).

DoD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016, 4-103.c., 5-203.b., and Chapter 5 and Chapter 8, paragraph 8-302.b.& g.'
  desc 'check', 'General Guidance:  

Standards of protection for most types of CUI are the same as for FOUO but some variance does exist.  Therefore, specific requirements for certain CUI may need to be checked against applicable references to ensure proper protection is afforded.  The checks are applicable to all forms of CUI: documents, AIS hard drives and storage media.

Checks:

For most CUI and FOUO specifically check to ensure the following standards are met: 

Check #1.  During working hours, reasonable steps shall be taken to minimize the risk of access by unauthorized personnel.  This would include things like placing cover sheets on FOUO documents and allowing unescorted access to areas where CUI (documents and AIS storage media) is processed/handled to only those persons with at least a favorably adjudicated National Agency Check (NAC). 

Check #2.  After working hours, FOUO information (documents and removable media) may be stored in unlocked containers, desks, or cabinets if Government or Government-contract building security is provided. If such building security is not provided or is deemed inadequate, the information (documents and removable media) shall be stored in locked desks, file cabinets, bookcases, locked rooms, etc.  In all cases FOUO and other CUI documents must be placed out of sight during non-working hours. While not required, recommending implementation of a clean desk policy would be appropriate.

Check #3.  Unescorted access to computer rooms or areas containing major items of AIS equipment processing CUI information (servers and network components) should only be granted to persons with at least a favorable NAC.  All others should be physically escorted. Access control measures such as reception personnel, guards, keyed locks, cipher locks or automated access control systems may be used to control access to such areas.                                      

TACTICAL ENVIRONMENT: The check is applicable for fixed (established) tactical processing environments where procedural documents (SOPs) should be in place.  Not applicable to a field/mobile environment.'
  desc 'fix', 'General Guidance:  

Standards of protection for most types of CUI are the same as for FOUO but some variance does exist.  Therefore, specific requirements for certain CUI may need to be checked against applicable references to ensure proper protection is afforded.  The fixes are applicable to all forms of CUI: documents, AIS hard drives and storage media.

Fixes applicable for FOUO:

For most CUI and FOUO specifically ensure the following standards are met: 

1.  During working hours, reasonable steps shall be taken to minimize the risk of access by unauthorized personnel.  This would include things like placing cover sheets on FOUO documents and allowing unescorted access to areas where CUI (documents and AIS storage media) is processed/handled to only those persons with at least a favorably adjudicated National Agency Check (NAC). 

2.  After working hours, FOUO information (documents and AIS storage media) may be stored in unlocked containers, desks, or cabinets if Government or Government-contract building security is provided. If such building security is not provided or is deemed inadequate, the information (documents and AIS storage media) shall be stored in locked desks, file cabinets, bookcases, locked rooms, etc.  In all cases FOUO and other CUI must be placed out of sight during non-working hours. While not required, implementation of a clean desk policy would be a good idea.  

3.  Unescorted access to computer rooms or areas containing major items of AIS equipment processing CUI information (servers and network components) should only be granted to persons with at least a favorable NAC.  All others should be physically escorted. Access control measures such as reception personnel, guards, keyed locks, cipher locks or automated access control systems may be used to control access to such areas.'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49276r770195_chk'
  tag severity: 'medium'
  tag gid: 'V-245845'
  tag rid: 'SV-245845r822912_rule'
  tag stig_id: 'IS-16.02.03'
  tag gtitle: 'IS-16.02.03'
  tag fix_id: 'F-49231r770196_fix'
  tag 'documentable'
  tag legacy: ['V-32261', 'SV-42578r3_rule']
end
