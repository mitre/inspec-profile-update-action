control 'SV-245824' do
  title 'Classified Working Papers are properly marked, destroyed when no longer needed, or treated as a finished document after 180 days.'
  desc 'Failure to properly mark or handle classified documents can lead to the loss or compromise of classified or sensitive information.

REFERENCES:

The Information Security Oversight Office (ISOO): http://www.archives.gov/isoo/   Implementing Directive for Protection of Classified (for Executive Order 13526), 32 CFR Parts 2001 and 2003 Classified National Security Information: paragraph 2001.24 Additional requirements, (d) Working papers and (m) Marking of electronic storage media.

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure A, paragraph 6.a. and Enclosure C, paragraph 21.h.(7).

NIST Special Publication 800-53 (SP 800-53), Rev 4, Control: MP-3 & PE-5(3).

DoD Manual 5200.01, Volume 2, 24 February 2012, SUBJECT: DoD Information Security Program: Marking of Classified Information; Enclosure 3, paragraph 13 and figure 11.

DoD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DoD Information Security Program: Protection of Classified Information; Enclosure 2, paragraph 13.

DoD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 4, Section 2, paragraph 4-214 and  Chapter 5, Section 2, paragraph 5-203.b.'
  desc 'check', 'Check any Working Papers, documents and/or Computer Media (CD, tape, flash drive, etc.)for compliance with the following guidance: 
 
Working papers are documents and material (includes computer media) accumulated or created in the preparation of finished documents and material. Working papers are marked in the same manner as a finished document at the same classification level when released by the originator outside the originating activity, retained more than 180 days from date of origin (30 days for SAPs), or filed permanently.  

Working papers containing classified information shall be:
 - Dated when created
 - Marked Top and Bottom with the highest classification of any information contained in the document
 - Annotated "WORKING PAPER"
                    
If any Automated Information System (AIS) hard drives or media are found to contain working papers or documents, the automated documents must be marked and handled in the same manner as hard copy documents.  If an entire AIS media storage device (tapes, diskettes, flash drives, CDs, DVDs, etc.) contains classified documents or data that are being treated as a working documents - then each individual working document on the media should be marked and handled as detailed above AND the media itself should be marked with the highest classification level, dated and marked "Working Documents".  

TACTICAL ENVIRONMENT APPLICABILITY: If classified working documents are found in a tactical environment they should be marked and handled according to the aforementioned guidance.'
  desc 'fix', 'Ensure that all Working Papers, documents and/or computer media comply with the following guidance:
  
Working papers are documents and material accumulated or created in the preparation of finished documents and material. Working papers are marked in the same manner as a finished document at the same classification level when released by the originator outside the originating activity, retained more than 180 days from date of origin (30 days for SAPs), or filed permanently.  

Working papers containing classified information shall be:
 - Dated when created
 - Marked Top and Bottom with the highest classification of any information contained in the document                                                     - Annotated "WORKING PAPER"
                    
If any Automated Information System (AIS) hard drives or media are found to contain working papers or documents, the automated documents must be marked and handled in the same manner as hard copy documents.  If an entire AIS media storage device (tapes, diskettes, flash drives, CDs, DVDs, etc.) contains classified documents or data that are being treated as a working documents - then each individual working document on the media should be marked and handled as detailed above AND the media itself should be marked with the highest classification level, dated and marked "Working Documents".'
  impact 0.3
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49255r770132_chk'
  tag severity: 'low'
  tag gid: 'V-245824'
  tag rid: 'SV-245824r822881_rule'
  tag stig_id: 'IS-04.03.01'
  tag gtitle: 'IS-04.03.01'
  tag fix_id: 'F-49210r770133_fix'
  tag 'documentable'
  tag legacy: ['V-31976', 'SV-42275r3_rule']
end
