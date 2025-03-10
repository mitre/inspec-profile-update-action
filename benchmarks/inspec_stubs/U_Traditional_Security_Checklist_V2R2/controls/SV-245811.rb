control 'SV-245811' do
  title 'Vault/Secure Room Storage Standards - IDS Performance Verification'
  desc 'Failure to test IDS functionality on a periodic basis could result in undetected alarm sensor or other system failure.  This in-turn could result in an undetected intrusion into a secure room  (AKA: collateral classified open storage area) and the undetected loss or compromise of classified material.

REFERENCES:

The Information Security Oversight Office (ISOO): http://www.archives.gov/isoo/   Implementing Directive for Protection of Classified (for Executive Order 13526), 32 CFR Parts 2001 and 2003 Classified National Security Information: paragraph 2001.43 Storage, (2) Secret.

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraphs 24.j. and 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: MP-4, PE-5, PE-6(1), PE-8 and MA-6.

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information:  Appendix to Enclosure 3, paragraphs 2.c. and 2.e.(7).

DoD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016, paragraphs 5-901., 5-904. and 5-905.

Testing and alarm verification procedures for specific sensors and other IDS equipment may be obtained from the Electronic Security Center (ESS), U.S. Army Engineering and Support Center, Huntsville, AL 35816:

ESS Question?  AskESSMCX@usace.army.mil'
  desc 'check', 'This check is concerned with verification of IDS functionality where IDS is used as a supplemental control for vaults or secure rooms/areas containing SIPRNet assets.  

Following are the required checks:  

Check #1. Checks of ALL individual alarm sensors (BMS, motion, glass break, etc.) will be conducted at least semi-annually.  

Check #2. Valid tests IAW best practices using government or industry standards and tools will be used to conduct the checks.  

Check #3. Written procedures will be developed for tests of each sensor type in use at a site.  

Check #4. Results of testing will be maintained on file for at least 1-year.  

TACTICAL ENVIRONMENT:  This check is applicable where Vaults/Secure Rooms are used to protect classified materials or systems in a tactical environment. The only exception will be for urgent (short term) tactical operations or other contingency situations where fixed facilities and equipment are not yet present or incapable of being used.'
  desc 'fix', 'Conduct verification of IDS functionality where IDS is used as a supplemental control for vaults or secure rooms/areas containing SIPRNet assets.  

Following are the required fixes:  

Fix #1. Ensure that checks of ALL individual alarm sensors (BMS, motion, glass break, etc.) are conducted at least semi-annually.  

Fix #2. Ensure that valid tests IAW best practices using government or industry standards and tools are used to conduct the checks.  

Fix #3. Ensure that written procedures are developed for tests of each sensor type in use at a site.  

Fix #4. Ensure that results of testing are maintained on file for at least 1-year.'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49242r770093_chk'
  tag severity: 'medium'
  tag gid: 'V-245811'
  tag rid: 'SV-245811r822867_rule'
  tag stig_id: 'IS-02.02.02'
  tag gtitle: 'IS-02.02.02'
  tag fix_id: 'F-49197r770094_fix'
  tag 'documentable'
  tag legacy: ['V-31279', 'SV-41547r3_rule']
end
