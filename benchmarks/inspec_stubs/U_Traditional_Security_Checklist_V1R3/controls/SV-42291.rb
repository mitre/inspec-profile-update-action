control 'SV-42291' do
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
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-40632r5_chk'
  tag severity: 'low'
  tag gid: 'V-31992'
  tag rid: 'SV-42291r3_rule'
  tag stig_id: 'IS-08.03.01'
  tag gtitle: 'Classified Monitors/Displays (Procedures for Obscuration of Classified Monitors)'
  tag fix_id: 'F-35924r2_fix'
  tag 'documentable'
  tag potential_impacts: 'RELATED VULS (STIG ID):

1.  STIG ID: FN-04.01.01.  This requirement concerns two related concerns.  First is control of physical access to areas containing US Only workstations/monitor screens, equipment, media or documents in working environments where Foreign Nationals are employed or present. Second, It also covers maintaining continuous observation and control of US Only classified information system removable storage media and documents within classified storage locations (such as SCIFs, secure rooms or vaults) where foreign nationals are present OR or placement in an approved safe.                         

2.  STIG ID: IS-08.01.01.  This requirement is specifically focused on checking physical controls in place to protect classified work stations (monitor screens/displays) from unauthorized viewing. This check does cover considerations for environments with US Only monitors and Foreign National (FN) presence but is not specific to only FN work environments.  It is also applicable to ALL environments where classified work stations (monitor screens/displays) are being used and there is a possibility of unauthorized viewing of the monitor screens by uncleared persons or those without a need-to-know.
 
3.  STIG ID: IS-08.01.02.  This requirement concerns maintaining control of Common Access Cards (CACs), SIPRNet tokens AND locking of computer work stations/monitor screens when unattended by removal of CACs, SIPRNet tokens or using Ctrl/Alt/Del.'
end
