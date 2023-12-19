control 'SV-245840' do
  title 'Classified Emergency Destruction Plans  - Develop and Make Available'
  desc 'Failure to develop emergency procedures can lead to the loss or compromise of classified or sensitive information during emergency situations.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 32.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: CP-4, PL-1 & RA-1.

DoDI 8500.01, SUBJECT: Cybersecurity, March 14, 2014, Enclosure 3, paragraph 9.b.(8)  (9) 

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information: Enclosure 2, paragraph 10.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, paragraph 5-104.

NIST SP 800-88, Guidelines for Media Sanitization

NSA/CSA Policy Manual 9-12, NSA/CSS Storage Device Declassification Manual

http://www.nsa.gov/ia/guidance/media_destruction_guidance/index.shtml'
  desc 'check', 'General Requirement: Plans shall be developed to protect, remove, or destroy classified material in case of fire, natural disaster, civil disturbance, terrorist activities, or enemy action, to minimize the risk of compromise, and for the recovery of classified information, if necessary, following such events.

Checks:            

Check #1. Check to ensure there is local site documentation for the emergency, protection, removal, and destruction of classified material and equipment. (CAT II)

Check #2. Also check to ensure that these instructions are readily available to the employee population.  Such plans should be posted on or near safes, exits to vaults and secure rooms or at any location where classified materials are stored. (CAT III)

TACTICAL ENVIRONMENT: The check is applicable for fixed (established) tactical processing environments where procedural documents (SOPs) should be in place.  Not applicable to a field/mobile environment.'
  desc 'fix', 'General Requirement: Plans shall be developed to protect, remove, or destroy classified material in case of fire, natural disaster, civil disturbance, terrorist activities, or enemy action, to minimize the risk of compromise, and for the recovery of classified information, if necessary, following such events.            

Ensure there is local site documentation for the emergency, protection, removal, and destruction of classified material and equipment. 

Also ensure that these instructions are readily available to the employee population.  Such plans should be posted on or near safes, exits to vaults and secure rooms or at any location where classified materials are stored.'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49271r770180_chk'
  tag severity: 'medium'
  tag gid: 'V-245840'
  tag rid: 'SV-245840r770182_rule'
  tag stig_id: 'IS-13.02.01'
  tag gtitle: 'IS-13.02.01'
  tag fix_id: 'F-49226r770181_fix'
  tag 'documentable'
  tag legacy: ['V-32132', 'SV-42449r3_rule']
end
