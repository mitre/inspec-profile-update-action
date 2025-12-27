control 'SV-245851' do
  title 'Classified Annual Review'
  desc 'Failure to conduct the annual review and clean out day can result in an excessive amount of classified (including IS storage media) being on hand and therefore being harder to account for, resulting in the possibility of loss or compromise of classified or sensitive information.

REFERENCES:

DOD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DOD Information Security Program: Protection of Classified Information; Enclosure 3, paragraph 17.b.

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND); Enclosure C, paragraph 34.a.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: PS-1.

DOD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 5, Section 7, paragraph 5-700.b.'
  desc 'check', 'Check #1. Check to ensure there are written procedures for the annual review and clean out of classified material. 

Check #2. Check to ensure there is a memorandum or some form of documentation covering results of the last clean out day. This is to validate actual completion of the requirement.

TACTICAL ENVIRONMENT: This check is not applicable for fixed (established) tactical processing environments and is not applicable to a field/mobile environment. Classified documents and materials in these environments should be properly disposed of as soon as possible after it is determined there is no longer a need for them.'
  desc 'fix', '1. Ensure there are written procedures for the annual review and clean out of classified material. 

2. Ensure the memorandum for the annual clean-out includes the number of security containers checked and the amount of classified material destroyed.'
  impact 0.3
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49282r770213_chk'
  tag severity: 'low'
  tag gid: 'V-245851'
  tag rid: 'SV-245851r917358_rule'
  tag stig_id: 'IS-17.03.01'
  tag gtitle: 'IS-17.03.01'
  tag fix_id: 'F-49237r917259_fix'
  tag 'documentable'
  tag legacy: ['V-32321', 'SV-42658r3_rule']
end
