control 'SV-245742' do
  title 'Protected Distribution System (PDS) Monitoring - Technical Inspections'
  desc 'A PDS that is not inspected, monitored and maintained as required could result in undetected access, sabotage or tampering of the unencrypted transmission lines. This could directly lead to the loss or compromise of classified.

REFERENCES: 
                                
CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 35.c.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016 Chapter 5, Section 4, paragraphs 5-402.c. and 5-403 
 
DoD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DoD Information Security Program: Protection of Classified Information, Encl 4, para 3.b. and 4.a.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls:  PE-4, SC-7, SC-8, IR-4, IR-6, and PE-19

CNSSI No. 7003, September 2015, Protected Distribution Systems (PDS), Section XI, paragraph 34. and Table 4. PDS Technical Inspection Schedule.'
  desc 'check', 'Check to ensure:
 
1. Technical inspections of PDS are conducted at least one or more times annually IAW Table 4. PDS Technical Inspection Schedule of the CNSSI 7003.
  
2. Checks and results must be documented and retained on file for a minimum of one year - or longer if required by the AO.

3. The person selected to accomplish the technical system inspection is trained to recognize changes in the technical aspects of PDS, e.g., by-pass circuitry, attachment or removal of devices or components, inappropriate or suspicious signal levels, and mechanical, TEMPEST, and RED/BLACK integrity of the PDS. If conducted by the CTTA this meets the requirement; otherwise, sufficient documented proof of training must be provided for the person conducting the inspection.
  
NOTE: This check is applicable within a tactical environment in a fixed facility but not applicable in a mobile field environment.'
  desc 'fix', 'Correction of this finding can only be made by complete compliance with all the following CNSSI 7003 requirements:

1. Technical inspections of PDS must be conducted at least one or more times annually IAW Table 4. PDS Technical Inspection Schedule, of the CNSSI 7003.
  
2. Checks and results must be documented and retained on file for a minimum of one year - or longer if required by the AO.
 
3. The person selected to accomplish the technical system inspection must be trained to recognize changes in the technical aspects of PDS, e.g., by-pass circuitry, attachment or removal of devices or components, inappropriate or suspicious signal levels, and mechanical, TEMPEST, and RED/BLACK integrity of the PDS. If conducted by the CTTA this meets the requirement; otherwise, sufficient documented proof of training must be provided for the person conducting the inspection.
 
NOTE: This check is applicable within a tactical environment in a fixed facility but not applicable in a mobile field environment.'
  impact 0.3
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49173r769886_chk'
  tag severity: 'low'
  tag gid: 'V-245742'
  tag rid: 'SV-245742r769888_rule'
  tag stig_id: 'CS-06.03.01'
  tag gtitle: 'CS-06.03.01'
  tag fix_id: 'F-49128r769887_fix'
  tag 'documentable'
  tag legacy: ['V-30977', 'SV-41021r3_rule']
end
