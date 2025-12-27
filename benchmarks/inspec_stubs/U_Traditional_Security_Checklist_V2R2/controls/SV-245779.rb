control 'SV-245779' do
  title 'Information Assurance - NIPRNET Connection Approval (CAP)'
  desc 'Failure to meet security standards and have approval before connecting to the NIPRNET can result in a vulnerability to the DISN.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Encl C, para 18.a.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
AC-3(1), AC-20

DoDI 8500.01, SUBJECT: Cybersecurity, March 14, 2014 

DoD Instruction 8510.01, SUBJECT: Risk Management Framework (RMF) for DoD Information Technology (IT)

CJCSI 6211.02D, DEFENSE INFORMATION SYSTEMS NETWORK (DISN) RESPONSIBILITIES,
Encl B, para 2.f. and Encl D, para 5.j.(1)

DISN Connection Process Guide:
http://disa.mil/network-services/enterprise-connections/connection-process-guide'
  desc 'check', '1. Check the NIPRNet connection approval package. Conduct a cursory review for any traditional security issues. 

2. Ensure the approval is current. The approval must come from the DISN Connection Approval Office (CAO).  

TACTICAL ENVIRONMENT: The check is applicable. The ATO/ATC and associated documentation should be found in a fixed HQ location where the ISSM/ISSO are located. When possible, documentation should be requested/sought before departing on trips to tactical locations.  Copies sent to the reviewers email (NIPR or SIPR depending on classification of document) can be used to validate compliance.'
  desc 'fix', '1. The NIPRNet connection approval package must be complete and accurate and the approval to connect (ATC) or Interim Approval to Connect (IATC) must be current. 

2. The approval must come from the DISN Connection Approval Office (CAO).'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49210r769997_chk'
  tag severity: 'medium'
  tag gid: 'V-245779'
  tag rid: 'SV-245779r769999_rule'
  tag stig_id: 'IA-08.02.01'
  tag gtitle: 'IA-08.02.01'
  tag fix_id: 'F-49165r769998_fix'
  tag 'documentable'
  tag legacy: ['V-31090', 'SV-41177r3_rule']
end
