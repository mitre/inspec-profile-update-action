control 'SV-245776' do
  title 'Information Assurance - System Training and Certification/ IA Personnel'
  desc 'Improperly trained personnel can cause serious system-wide/network-wide problems that render a system/network unstable.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Encl A, para 11.

DoDI 8500.01, SUBJECT: Cybersecurity, March 14, 2014 , Encl 2, para 9.g., 13.k.(2); Encl 3, para 10. a-e

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: AT-2, AT-3, CP-3, IR-2

DoD 8570.01-M, Information Assurance Workforce Improvement Program, Appendix 3

DoDD 8140.01, Cyberspace Workforce Management, 11 Aug 15, paragraphs 3.c. and 9.j.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 8, paragraphs 8-103.a.(6) & 8-302.a.'
  desc 'check', '1. Check records for required training/certification of (IA) IAM/IAT personnel. In addition to the initial and recurring (annual) training requirements every system user must undergo, the IA staff such as ISSM, ISSO, SA, NSO must be part of an organizational certification program IAW DoD 8570.01-M, Workplace Improvement Program.  

2. Ensure this certification program is in place and that training/certification requirements are documented for each IA staff member, which includes current certification level: IAM (I-III) or IAT (I-III). 

TACTICAL ENVIRONMENT: In a tactical environment records should be maintained at fixed locations where IA and security staff are working. This check is not applicable to units in a mobile/field environment.'
  desc 'fix', '1. A program must be in place to establish and document required training/certification of (IA) IAM/IAT personnel. 

2. In addition to the initial and recurring (annual) training requirements every system user must undergo, the IA staff such as ISSM, ISSO, SA, NSO must be part of an organizational certification program IAW DoD 8570.01-M, IA Workplace Improvement Program. 

3. Training/certification requirements must be documented for each IA staff member to include their current certification level: IAM (I-III) or IAT (I-III).'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49207r769988_chk'
  tag severity: 'medium'
  tag gid: 'V-245776'
  tag rid: 'SV-245776r769990_rule'
  tag stig_id: 'IA-06.02.01'
  tag gtitle: 'IA-06.02.01'
  tag fix_id: 'F-49162r769989_fix'
  tag 'documentable'
  tag legacy: ['V-31013', 'SV-41060r3_rule']
end
