control 'SV-42288' do
  title 'Handling of Classified - Use of Cover Sheets on Documents Removed from Secure Storage'
  desc 'Failure to protect readable classified information printed from classified systems such as SIPRNet when removed from secure storage can lead to the loss or compromise of classified or sensitive information.

REFERENCES:

The Information Security Oversight Office (ISOO): http://www.archives.gov/isoo/   Implementing Directive for Protection of Classified (for Executive Order 13526), 32 CFR Parts 2001 and 2003 Classified National Security Information:Subpart H—Standard Forms § 2001.80 Prescribed standard forms. 

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Control: MP-1 and MP-5.

DoD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DoD Information Security Program: Protection of Classified Information; Enclosure 2, paragraph 8.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, paragraph 4-210.a.'
  desc 'check', 'During the review/walk-around be observant for classified documents without cover sheets.  Unless an employee is specifically working on the document - a cover sheet must be placed on it to ensure classified information is not inadvertently exposed.  If the document without a cover sheet is located in a SCIF, Secret or TS vault or secure room - this should not be written as a finding; however, highly recommend use of cover sheets as a best security practice for enforcement of need-to-know.  If the document w/o cover sheet is found in a Secret Controlled Access Area (CAA) or below, this should be made a finding.    

TACTICAL ENVIRONMENT: The check is applicable for fixed tactical classified processing environments.  It is assumed the type of equipment referenced will be in a fixed environment. Not applicable to a field/mobile environment.'
  desc 'fix', 'Ensure classified handling procedures address use of cover sheets on classified documents printed from systems such as SIPRNet, when the documents are removed from secure storage.

Address use of cover sheets during initial and annual refresher security training.

Periodically check areas for use of cover sheets.

While not required by regulation it is good security practice to use document cover sheets in a SCIF, Secret or TS vault or secure room to prevent inadvertent access to classified information by persons without need-to-know and uncleared visitors to such classified areas.'
  impact 0.3
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-40627r5_chk'
  tag severity: 'low'
  tag gid: 'V-31989'
  tag rid: 'SV-42288r3_rule'
  tag stig_id: 'IS-07.03.02'
  tag gtitle: 'Handling of Classified - Use of Cover Sheets on Documents'
  tag fix_id: 'F-35918r3_fix'
  tag 'documentable'
end
