control 'SV-245849' do
  title 'Controlled Unclassified Information (CUI) - Local Policy and Procedure'
  desc 'Failure to handle CUI in an approved manner can result in the loss or compromise of sensitive information.

REFERENCES:

Executive Order 13556, Controlled Unclassified Information (CUI)

The Information Security Oversight Office (ISOO): https://www.archives.gov/cui

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND); Enclosure C, paragraph 25.d.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: PE-1, PL-1 and SI-1.

DODI 5200.48 Controlled Unclassified Information (CUI)

DOD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 7, Section 1, paragraph 7-101.a.(2).'
  desc 'check', 'General Policy Guidance: All personnel of the Department of Defense are personally and individually responsible for properly protecting classified information and Controlled Unclassified Information (CUI) under their custody and control. All officials within the Department of Defense who hold command, management, or supervisory positions have specific, non-delegable responsibility for the quality of implementation and management of the information security program within their areas of responsibility. 

Check:
This check is specifically to ensure there are local written procedures for handling, marking, storing, destroying and transmitting Controlled Unclassified Information.  

TACTICAL ENVIRONMENT: The check is applicable for fixed (established) tactical processing environments where procedural documents (SOPs) should be in place. Not applicable to a field/mobile environment.'
  desc 'fix', 'General Policy Guidance: All personnel of the Department of Defense are personally and individually responsible for properly protecting classified information and Controlled Unclassified Information (CUI) under their custody and control. All officials within the Department of Defense who hold command, management, or supervisory positions have specific, non-delegable responsibility for the quality of implementation and management of the information security program within their areas of responsibility. 

Fix:
Ensure there are local written procedures for handling, marking, storing, destroying and transmitting Controlled Unclassified Information.'
  impact 0.3
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49280r917253_chk'
  tag severity: 'low'
  tag gid: 'V-245849'
  tag rid: 'SV-245849r917356_rule'
  tag stig_id: 'IS-16.03.01'
  tag gtitle: 'IS-16.03.01'
  tag fix_id: 'F-49235r917254_fix'
  tag 'documentable'
  tag legacy: ['V-32156', 'SV-42473r3_rule']
end
