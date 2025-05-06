control 'SV-42455' do
  title 'Security Incident/Spillage - Lack of Procedures or Training for Handling and Reporting'
  desc 'Failure to report possible security compromise can result in the impact of the loss or compromise of classified information not to be evaluated, responsibility affixed, or a plan of action developed to prevent recurrence of future incidents.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraphs 6.k.(1), 9.c., 18.k.(e),  26.s.(6), 29. and 31.c.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: AT-1, AT-2, AU-2, AU-7, AU-11, IR-1, IR-2, IR-4, IR-5, IR-6, IR-7, IR-8 and IR-9.

DoDI 8500.01, SUBJECT: Cybersecurity, March 14, 2014, Enclosure 3, paragraph 7.g. and 19.d.

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information: Enclosure 6, Appendix 1 to Encl 6, Appendix 2 to Encl 6  and Enclosure 7, paragraph 5. 

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, paragraphs 1-303, 1-304, 1-400, 1-401 and 8-302.i.

CNSSP No. 18, National Policy on Classified Information Spillage

CNSSI 1001, National Instruction on Classified Information Spillage'
  desc 'check', 'General requirement:

Anyone finding classified information out of proper control shall, if possible, take custody of and safeguard the material and immediately notify the appropriate security authorities. Secure communications should be used for notification whenever possible. Every civilian employee and Active, Reserve, and National Guard Military member of the Department of Defense, and every DoD contractor or employee of a contractor working with classified material, as provided by the terms of the contract, who becomes aware of the loss or potential compromise of classified information shall immediately report it to the head of his or her local activity and to the activity security manager.  Prompt reporting of security incidents ensures incidents are properly investigated and necessary actions are taken to negate or minimize the adverse effects of an actual loss or unauthorized disclosure of classified information and to preclude recurrence through a properly tailored, and up-to-date security education and awareness program. In cases where compromise has been ruled out and there is no adverse effect on national security, a common sense approach to the early resolution of an incident at the lowest appropriate level is encouraged. All security incidents involving classified information shall involve a security inquiry, a security investigation, or both.

Reviewer Checks:

Check #1. Check to ensure the site or organization has written procedures on reporting possible security incidents.  

Check #2. Check to ensure personnel within the organization have training to be able to know when to report a possible security incident and who to report it to. 

Check #3. Check to ensure employees know what to do when discovering classified material unsecure or out of proper control.  Ask random employees if they know what to do if they discover a security incident?
                                                    TACTICAL ENVIRONMENT: Classified material that is discovered not properly secured must immediately be secured and the incident reported - regardless of environment.'
  desc 'fix', 'General requirement:
Anyone finding classified information out of proper control shall, if possible, take custody of and safeguard the material and immediately notify the appropriate security authorities. Secure communications should be used for notification whenever possible. Every civilian employee and Active, Reserve, and National Guard Military member of the Department of Defense, and every DoD contractor or employee of a contractor working with classified material, as provided by the terms of the contract, who becomes aware of the loss or potential compromise of classified information shall immediately report it to the head of his or her local activity and to the activity security manager.  Prompt reporting of security incidents ensures incidents are properly investigated and necessary actions are taken to negate or minimize the adverse effects of an actual loss or unauthorized disclosure of classified information and to preclude recurrence through a properly tailored, and up-to-date security education and awareness program. In cases where compromise has been ruled out and there is no adverse effect on national security, a common sense approach to the early resolution of an incident at the lowest appropriate level is encouraged. All security incidents involving classified information shall involve a security inquiry, a security investigation, or both.

Fixes:  

1. Ensure the site or organization has written procedures on reporting possible security incidents.  

2. Ensure personnel within the organization have training to be able to know when to report a possible security incident and who to report it to. 

3. Ensure employees know what to do when discovering classified material unsecure or out of proper control.  Verify by asking random employees if they know what to do if they discover a security incident.'
  impact 0.5
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-40663r7_chk'
  tag severity: 'medium'
  tag gid: 'V-32138'
  tag rid: 'SV-42455r3_rule'
  tag stig_id: 'IS-14.02.01'
  tag gtitle: 'Security Incident/Spillage - Handling and Reporting'
  tag fix_id: 'F-36074r3_fix'
  tag 'documentable'
  tag responsibility: 'Security Manager'
end
