control 'SV-245795' do
  title 'Information Security (INFOSEC) - Vault/Secure Room Storage Standards - Door Combination Lock  Meeting Federal Specification FF-L-2740'
  desc 'Failure to meet Physical Security storage standards could result in the undetected loss or compromise of classified material.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Encl A, paragraph 7.f.; Encl C, paragraph 10.a., and 10.b.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
MP-4, PE-3 and PE-5

DOD Manual 5200.01, Volume 3, SUBJECT: DOD Information Security Program: Protection of Classified Information: Encl 3, para 1.d, 2., 3.a.(2), 3.b.(1), 6.a.(2), 7. and Appendix to Encl 3, para 1.b.(3).

Information Security Oversight Office, 32 CFR Parts 2001 and 2003 Classified National Security Information

DOD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 5, paragraphs 5-303., 5-306., 5-307.c., 5-310., 5-312., 5-313., 5-314. & Section 8, Construction Requirements.'
  desc 'check', '*This check is specifically for vaults and secure rooms or open storage areas containing inspectable SIPRNet assets*:

Check the primary ingress/egress door to ensure a proper combination lock is installed and is being used. Door must be equipped with a built-in GSA-approved combination lock meeting Federal Specification FF-L-2740, such as the X07, X09, or Kaba Mas X-10 locks. 

NOTE: The use of automated entry control systems (AECS) is encouraged to control access to secure room space during working hours; however, electrically actuated locks (e.g., cypher and magnetic access card locks) do not afford by themselves the required degree of protection for classified information and must not be used as a substitute for the combination locks meeting Federal Specification FF-L-2740.
  
TACTICAL ENVIRONMENT: This check is applicable where vaults or secure rooms are used to protect classified materials or systems. The only exception will be for urgent (short term) tactical operations or other contingency situations where fixed facilities and equipment are not yet present or incapable of being used.'
  desc 'fix', '*This requirement is specifically for vaults and secure rooms or open storage areas containing inspectable SIPRNet assets*:

The primary ingress/egress door must be equipped with a proper combination lock that is installed properly and is being used. Door must be equipped with a built-in GSA-approved combination lock meeting Federal Specification FF-L-2740, such as the X07, X09, and Kaba Mas X-10 locks. 

NOTE: The use of automated entry control systems (AECS) is encouraged to control access to secure room space during working hours; however, electrically actuated locks (e.g., cypher and magnetic access card locks) do not afford by themselves the required degree of protection for classified information and must not be used as a substitute for the combination locks meeting Federal Specification FF-L-2740.'
  impact 0.7
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49226r917217_chk'
  tag severity: 'high'
  tag gid: 'V-245795'
  tag rid: 'SV-245795r917344_rule'
  tag stig_id: 'IS-02.01.01'
  tag gtitle: 'IS-02.01.01'
  tag fix_id: 'F-49181r917218_fix'
  tag 'documentable'
  tag legacy: ['V-31267', 'SV-41529r3_rule']
end
