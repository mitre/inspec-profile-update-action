control 'SV-245817' do
  title 'Vault/Secure Room Storage Standards - Automated Entry Control System (AECS) Records Maintenance, which includes documented procedures for granting and removal of access.'
  desc 'Failure to document procedures for removal of access and inadequate maintenance of access records for both active and removed persons could result in unauthorized persons having unescorted access to vaults, secure rooms or collateral classified open storage areas where classified information is processed and stored. 

REFERENCES:

The Information Security Oversight Office (ISOO): http://www.archives.gov/isoo/   Implementing Directive for Protection of Classified (for Executive Order 13526), 32 CFR Parts 2001 and 2003 Classified National Security Information: paragraph 2001.43 Storage, (2) Secret.

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: PE-1, PE-2, PE-3, PE-6 and PE-8.

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information:  Appendix to Enclosure 3, paragraph 3.a(4) and (7)

DoD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 5, paragraph 5-313.i.'
  desc 'check', "Requirements Summary:

A procedure must be established for removal of an individual's authorization to enter the secure room area upon reassignment, transfer, or termination, or when the individual's access is suspended, revoked, or downgraded to a level lower than the former access level.  Records shall also be accurately maintained reflecting active assignment of ID badge/card, PIN, level of access, and similar system-related records. Records concerning personnel removed from the system shall be retained for a minimum of 90 days.

CHECKS:

Check #1. Check to ensure that records reflecting active assignment of ID badge/card, PIN, level of access, and similar system-related records are accurately maintained.  (CAT II)

Check #2. Check to ensure there is a documented procedure for removal of persons from the Automated Entry Control System.  (CAT III)

Check #3. Check to ensure that records concerning personnel removed from the system are retained for a minimum of 90 days.  (CAT III)

TACTICAL ENVIRONMENT:  This check is applicable where Vaults/Secure Rooms are used to protect classified materials or systems in a tactical environment. The only exception will be for urgent (short term) tactical operations or other contingency situations where fixed facilities and equipment are not yet present or incapable of being used."
  desc 'fix', '1.  Ensure there is a documented procedure for removal of persons from the Automated Entry Control System.

2.  Ensure that records reflecting active assignment of ID badge/card, PIN, level of access, and similar system-related records are accurately maintained.  

3. Ensure that records concerning personnel removed from the system are retained for a minimum of 90 days.'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49248r770111_chk'
  tag severity: 'medium'
  tag gid: 'V-245817'
  tag rid: 'SV-245817r822874_rule'
  tag stig_id: 'IS-02.02.08'
  tag gtitle: 'IS-02.02.08'
  tag fix_id: 'F-49203r770112_fix'
  tag 'documentable'
  tag legacy: ['V-31548', 'SV-41831r3_rule']
end
