control 'SV-245831' do
  title 'Classified Monitors/Displays (Procedures for Obscuration of Classified Monitors) - protection from uncleared persons or those without a need-to-know.'
  desc 'Failure to develop procedures and training for employees to cover responsibilities and methods for limiting the access of unauthorized personnel to classified information reflected on information system monitors and displays can result in the loss or compromise of classified information.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
PE-1, PS-1, PE-5, PS-3(1) & (2) and PS-6(2).

DoDI 8500.01, SUBJECT: Cybersecurity, March 14, 2014 , Enclosure 3, paragraph 7.

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information, Enclosure 2 paragraph 14.a.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 3, paragraph 3-107.f.'
  desc 'check', 'Check to ensure there are written procedures for employees to follow to keep classified monitors from being viewed by unauthorized persons.  Procedures should include when to cover or turn-off classified monitors - such as when visitors are announced, importance of maintaining monitor positioning for privacy, pulling of window shades, blinds, etc.  Procedures must be tailored to the physical environment and mission operations of the organization.  

TACTICAL ENVIRONMENT: The check is applicable for fixed (established) tactical processing environments.  Not applicable to a field/mobile environment.'
  desc 'fix', 'Ensure there are written procedures for employees to follow to keep classified monitors from being viewed by unauthorized persons.  Procedures should include when to cover or turn-off classified monitors - such as when visitors are announced, importance of maintaining monitor positioning for privacy, pulling of window shades, blinds, etc.  Procedures must be tailored to the physical environment and mission operations of the organization.'
  impact 0.3
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49262r770153_chk'
  tag severity: 'low'
  tag gid: 'V-245831'
  tag rid: 'SV-245831r770155_rule'
  tag stig_id: 'IS-08.03.01'
  tag gtitle: 'IS-08.03.01'
  tag fix_id: 'F-49217r770154_fix'
  tag 'documentable'
  tag legacy: ['V-31992', 'SV-42291r3_rule']
end
