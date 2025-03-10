control 'SV-245777' do
  title 'Information Assurance/Cybersecurity Training for System Users'
  desc 'Improperly trained personnel can cause serious system-wide/network-wide problems that render a system/network unstable.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Encl A, para 11.a.

DoDI 8500.01, SUBJECT: Cybersecurity, March 14, 2014 , Encl 2, para 13.l.; Encl 3, para 10.c., 17.c., 19.c., 21.j.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: AT-2, AT-3, CP-3, IR-2

DoD 8570.01-M, Information Assurance Workforce Improvement Program, paragraphs C.1.4.1.4,5.1., C.1.4.4.3., C.5.2.1.5., Table C.4.T.3. - M.I.6., Table C.4.T.5. - M.II.18.; Chapter 6 in its entirety for minimum user training requirements.

DoDD 8140.01, Cyberspace Workforce Management, 11 Aug 15, paragraph 9.b.

DoD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 8, paragraphs 8-101.c., 8-103.a., & 8-302.j.'
  desc 'check', 'Check training records for required initial and recurring (annual) training requirements every system user must undergo in accordance with Chapter 6 of the DoD 8570.01-M, Information Assurance Workforce Improvement Program. Ensure 100% of initial training briefings are accomplished and at least 95% of employees have completed annual training.  Note that while 100% completion of annual training is the goal, employees on extended leave. TDY or other circumstances make this a difficult thing to accomplish. 

All training accomplished must be documented. Anything less will be a finding.

TACTICAL ENVIRONMENT: In a tactical environment records should be maintained at fixed locations where IA and security staff are working. This check is not applicable to personnel in units in a mobile/field environment.'
  desc 'fix', '1. All system users must take both initial and recurring (annual) cybersecurity training based on applicable regulatory requirements that every system user must undergo, primarily in accordance with Chapter 6 of the DoD 8570.01-M, Information Assurance Workforce Improvement Program. 

2. Ensure 100% of initial training briefings are accomplished and at least 95% of employees have completed annual training. Note that while 100% completion of annual training is the goal, employees on extended leave. TDY or other circumstances make this a difficult thing to accomplish. 

3. All training accomplished must be documented for each individual user.'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49208r769991_chk'
  tag severity: 'medium'
  tag gid: 'V-245777'
  tag rid: 'SV-245777r822837_rule'
  tag stig_id: 'IA-06.02.02'
  tag gtitle: 'IA-06.02.02'
  tag fix_id: 'F-49163r769992_fix'
  tag 'documentable'
  tag legacy: ['V-31082', 'SV-41133r3_rule']
end
