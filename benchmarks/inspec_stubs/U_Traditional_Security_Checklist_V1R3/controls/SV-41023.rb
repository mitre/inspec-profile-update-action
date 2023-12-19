control 'SV-41023' do
  title 'Protected Distribution System (PDS) Monitoring - Reporting Incidents'
  desc 'A PDS that is not inspected, monitored and maintained as required could result in undetected access, sabotage or tampering of the unencrypted transmission lines. This could directly lead to the loss or compromise of classified.

REFERENCES: 
                                
CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 35.c.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016 Chapter 5, Section 4, paragraphs 5-402.c. and 5-403 

DoD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DoD Information Security Program: Protection of Classified Information, Encl 4, para 3.b. and 4.a.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls:  PE-4, SC-7, SC-8, IR-4, IR-6, and PE-19

CNSSI No. 7003, September 2015, Protected Distribution Systems (PDS), Section XI, paragraph 32.'
  desc 'check', '1. Check to ensure there are procedures written that cover how to handle all possible types of potential PDS incidents.
 
2. Check daily and technical inspection results (logs) for evidence of discovered PDS anomalies.
  
3. Ensure any incidents of tampering, penetration, or unauthorized interception were reported immediately to the PDS Approving Authority and the local security/law enforcement authority. 

4. Subject to law enforcement procedures, which take precedence, check to ensure the PDS was not used until the incident was assessed and its security status determined.
 
5. If discontinued use of the PDS is or was not practical, check to ensure users of all impacted PDS were notified of the possible breach in security, and instructed that use of systems running on the PDS be limited to the greatest extent possible.
  
6. Discovery of an anomaly in the PDS that is not properly reported and resolved is a finding. All discoveries must be documented and such documentation retained indefinitely -for as long as the PDS remains functional.
  
NOTES:

1. This check is applicable to tactical environments.  Incidents of possible tampering must be reported to the PDS approving authority in as expeditious a manner as possible.

2. Even if there is no finding, in the reviewer notes provide a brief note of any reported incidents or anomalies previously noted by the site, including the date it was initially noted.'
  desc 'fix', '1. A procedure must be written that covers how to handle all possible types of potential PDS incidents.
 
2. ALL incidents of suspected or actual tampering, penetration, or unauthorized interception must be reported immediately to the PDS Approving Authority and the local security/law enforcement authority.

3. Subject to law enforcement procedures, which take precedence, the PDS must not be used until the incident is assessed and its security status determined.
 
4. If discontinued use of the PDS is or was not practical, all users of impacted PDS must be notified of the possible breach in security and instructed that use of systems running on the PDS be limited to the greatest extent possible.
 
5. All discoveries must be documented and such documentation retained indefinitely -for as long as the PDS remains functional.'
  impact 0.5
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-39642r8_chk'
  tag severity: 'medium'
  tag gid: 'V-30979'
  tag rid: 'SV-41023r3_rule'
  tag stig_id: 'CS-06.02.02'
  tag gtitle: 'PDS Monitoring - Reporting Incidents'
  tag fix_id: 'F-34790r7_fix'
  tag 'documentable'
  tag severity_override_guidance: 'CAT II is the default severity level when finding an incident that has not been properly reported and investigated.

CAT III is the severity level if the ONLY finding is that a written procedure for reporting PDS anomalies is not available and no anomaly in the PDS has been discovered.'
end
