control 'SV-245860' do
  title 'Out-processing Procedures for Departing or Terminated Employees (Military, Government Civilian and Contractor)'
  desc 'Failure to properly out-process through the security section allows the possibility of continued (unauthorized) access to the facility and/or the systems.

REFERENCES:

DoD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DoD Information Security Program: Protection of Classified Information Appendix to Encl 3, paragraph 3.a.(4). and Enclosure 5, paragraph 9.
 
DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 1, paragraph 1-206. and Chapter 3, paragraph 3-109. 

DoD Manual 5200.02, Procedures for the DoD Personnel Security Program (PSP), April 3, 2017,
Chapter 12, paragraph 12.1.b.&f., Appendix G.2. Definitions, JPAS
 
NIST Special Publication 800-53 (SP 800-53) Controls: AC-1, AC-2, PE-3, PS-4, and PS-5 

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), 9 February 2011 Enclosure C, para 11'
  desc 'check', 'Check to ensure the organization has documented out-processing procedures. 

Review a sampling of personnel security files of departed personnel to ensure compliance.  Files of departed personnel should be maintained by an organization for at least 90-days.

Ensure the procedures and records of departed employees reviewed include:
-Removal from access to Government Information Systems, 
- Turning in all access badges, classified and/or sensitive information,
- Removal from automated entry control systems (AECS) and 
- Signing of an SF 312 acknowledging a security debriefing.

NOTE: The SF 312 is only applicable for those persons holding a security clearance.  

TACTICAL ENVIRONMENT: The check is applicable for fixed (established) tactical processing environments where procedural documents (SOPs) and personnel records should be in place.  Not applicable to a field/mobile environment.'
  desc 'fix', 'Ensure there are local procedures covering the out-processing of departing employees (Military, Government Civilian and Contractor) and that records of departed employees on-hand reflect that out-processing was conducted.  Out-processing records should be retained for a minimum of 90-days.

 Ensure that out-processing procedures and records include:
-Removal from access to Government Information Systems, 
- Turning in all access badges, classified and/or sensitive information,
- Removal from automated entry control systems (AECS) and 
- Signing of an SF 312 acknowledging a security debriefing.

NOTE: The SF 312 is only applicable for those persons holding a security clearance.'
  impact 0.3
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49291r770240_chk'
  tag severity: 'low'
  tag gid: 'V-245860'
  tag rid: 'SV-245860r770242_rule'
  tag stig_id: 'PE-07.03.01'
  tag gtitle: 'PE-07.03.01'
  tag fix_id: 'F-49246r770241_fix'
  tag 'documentable'
  tag legacy: ['V-32425', 'SV-42762r3_rule']
end
