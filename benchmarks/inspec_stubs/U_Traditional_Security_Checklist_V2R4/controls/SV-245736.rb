control 'SV-245736' do
  title 'Protected Distribution System (PDS) Construction - Visible for Inspection and Marked'
  desc 'A PDS that is not completely visible for inspection and easily identified cannot be properly inspected and monitored as required, which could result in undetected access, sabotage or tampering of the unencrypted transmission lines. This could directly lead to the loss or compromise of classified.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 35.c.

DoD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016 Chapter 5, Section 4, paragraphs 5-402.c. and 5-403   

DoD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DoD Information Security Program: Protection of Classified Information, Encl 4, para 3.b. and 4.a.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls:  PE-4, SC-7, SC-8, and RA-6

CNSSI No. 7003, September 2015, Protected Distribution Systems (PDS), Section VIII, paragraphs 23.c. and 24.'
  desc 'check', 'Check to ensure: 

1. The PDS is visible for inspection. The Category 2 (Hardened) carrier should be installed in plain view to meet both Visual and Technical inspection requirements. 

2. The PDS is not installed above a false ceiling, below a false floor, or inside a wall unless it is clear that all portions within the wall, above the ceiling or below the floor are inspectable by means identified in the PDS approval request.
 
NOTE: If the PDS cannot be installed in plain view, or is rendered un-inspectable, then the PDS must be an alarmed carrier.

3. The PDS is marked to make it easily identifiable to the inspector. The markings should be placed at sufficient intervals to facilitate inspections, however, intervals shall not exceed 3 meters (approximately 10 feet).
 
4. The PDS markings consist of tape, paint, cable tags, or any other suitable method that does not obscure or impair inspection.
 
5. The PDS is not labeled as a PDS, or labeled with text that would indicate that it carries National Security Information (NSI).
 
6. The markings are not red, since this color is often used to identify fire sprinkler systems, fire alarm wires, and NSI.
 
7. The PDS is not painted unless using a distribution system that has a factory painted coating.'
  desc 'fix', '1. The PDS must be visible for inspection. The Category 2 (Hardened) carrier should be installed in plain view to meet both Visual and Technical inspection requirements.
 
2. The PDS should not be installed above a false ceiling, below a false floor, or inside a wall unless it is clear that all portions within the wall, above the ceiling or below the floor are inspectable by means identified in the PDS approval request.
 
NOTE: If the PDS cannot be installed in plain view, or is rendered un-inspectable, then the PDS must be an alarmed carrier.

3. The PDS must be marked to make it easily identifiable to the inspector. The markings should be placed at sufficient intervals to facilitate inspections, however, intervals shall not exceed 3 meters (approximately 10 feet).
 
4. The PDS markings must consist of tape, paint, cable tags, or any other suitable method that does not obscure or impair inspection.
 
5. The PDS must not be labeled as a PDS, or labeled with text that would indicate that it carries National Security Information (NSI).
 
6. The markings must not be red, since this color is often used to identify fire sprinkler systems, fire alarm wires, and NSI.
 
7. The PDS must not be painted unless using a distribution system that has a factory painted coating.'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49167r769868_chk'
  tag severity: 'medium'
  tag gid: 'V-245736'
  tag rid: 'SV-245736r822803_rule'
  tag stig_id: 'CS-04.02.01'
  tag gtitle: 'CS-04.02.01'
  tag fix_id: 'F-49122r769869_fix'
  tag 'documentable'
  tag legacy: ['V-30940', 'SV-40982r4_rule']
end
