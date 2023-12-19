control 'SV-245832' do
  title 'End-of-Day Checks - Organizations that process or store classified information must establish a system of security checks at the close of each duty and/or business day to ensure that any area where classified information is used or stored is secure. SF 701, Activity Security Checklist, shall be used to record such checks.'
  desc 'Failure to have written guidance to provide guidance for end-of-day (EOD) checks could lead to  such checks not being properly conducted.  If EOD checks are not properly conducted the loss or improper storage of classified material might not be promptly discovered.  This could result in a longer duration of the security deficiency before corrective action is taken and make discovery of factual information concerning what caused the security incident and assigning responsibility and remedial actions more difficult. Ultimately the failure to perform consistent EOD checks can lead to the loss or compromise of classified or sensitive information.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: PE-1, PE-3(2), MP-4 

DoDI 8500.01, SUBJECT: Cybersecurity, March 14, 2014 , Enclosure 3, paragraph 7.

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information, Enclosure 2, paragraph 9. 

DoD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 5, paragraph 5-102.'
  desc 'check', 'Organizations that process or store classified information must establish a system of security checks at the close of each duty and/or business day to ensure that any area where classified information is used or stored is secure. SF 701, "Activity Security Checklist," shall be used to record such checks. An integral part of the security check system shall be the securing of all vaults, secure rooms, and containers used for storing classified material. SF 702, "Security Container Check Sheet," shall be used to record each opening, closing, and verification checks of these storage mediums.  Area verification checks will be recorded on the SF 701 upon completion of end-of-day checks.  Recommended end-of-day checks, which should be included on the SF 701 are:                                                      
a.  Activation of Intrusion Detection System (IDS) alarm sensors where applicable.
b.  All classified material has been properly stored. 
c.  Removal of CAC Cards and SIPRNet tokens from workstations.
d.  All windows, doors or other openings are properly secured.                                          
e.  Verification of lock box closure for SIPRNet wall jacks and PDS lines, where applicable.
f.  Additional checks such as turning off of coffee pots and lights, power-off of printers/MFDs, securing of STE keys, etc. can be identified and accomplished as part of the check.
g.  The SF 701, Activity Security Checklist shall be used to record these checks, to include after hours, weekend and holiday activities.                                               

Results of end-of-day checks (SF 701 forms) should be retained for at least 30 days after completion of the monthly form (or otherwise as required by Component records management schedules) to ensure availability for audits and resolution of subsequent discovery of security incidents or discrepancies.
                                       
TACTICAL ENVIRONMENT:  This check is applicable in a fixed operational facility in a tactical environment if classified equipment is used or documents or media are created/extracted from the SIPRNet.  The only exception will be for urgent (short term) tactical operations or other contingency situations where fixed facilities and equipment are not yet present or incapable of being used.'
  desc 'fix', 'Ensure that areas where classified information is processed or stored have an established system of security checks implemented at the close of each duty and/or business day to ensure that any area where classified information is used or stored is secure. SF 701, "Activity Security Checklist," must be used to record these checks. 

In addition to the SF 701, the responsible site or organization should have a written procedure to outline the end-of-day check process and to guide checkers with their duties. For instance the procedure should include instructions on how to handle any classified information that is found outside of proper storage.

An integral part of the security check system must incorporate the securing of all vaults, secure rooms, and containers used for storing classified material. SF 702, "Security Container Check Sheet," must be used to record each opening, closing, and verification checks of these storage mediums.  

Area verification checks will be recorded on the SF 701 upon completion of end-of-day checks.  Following are recommended end-of-day checks, which should be included on the SF 701, but ultimately the checks must be tailored to fit the physical configuration and mission of the site:                                                      
a. Activation of Intrusion Detection System (IDS) alarm sensors where applicable.
b.  All classified material has been properly stored.                                                     
c.  Removal of CAC Cards and SIPRNet tokens from workstations.
d.  All windows, doors or other openings are properly secured.                                          
e.  Verification of lock box closure for SIPRNet wall jacks and PDS lines, where applicable.
f.  Additional checks such as turning off of coffee pots and lights, power-off of printers/MFDs, securing of STE keys, etc. can be identified and accomplished as part of the check.
g. The SF 701, Activity Security Checklist shall be used to record these checks, to include after hours, weekend and holiday activities.
                                               
Results of end-of-day checks (SF 701 forms) should be retained for at least 30 days (or otherwise as required by Component records management schedules) after completion of the monthly form to ensure availability for audits and resolution of subsequent discovery of security incidents or discrepancies.  While 24/7 operational areas storing classified materials do not necessarily require end-of-day (EOD) checks it is highly recommended that a system of checks be instituted (similar to EOD checks) upon each change of shift.  Such checks jointly conducted by incoming and outgoing supervisors can be used to verify the integrity of safes and classified equipment/materials under their control and can be used to narrow the window of time for a preliminary inquiry should a security incident occur.'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49263r822891_chk'
  tag severity: 'medium'
  tag gid: 'V-245832'
  tag rid: 'SV-245832r822892_rule'
  tag stig_id: 'IS-09.02.01'
  tag gtitle: 'IS-09.02.01'
  tag fix_id: 'F-49218r770157_fix'
  tag 'documentable'
  tag legacy: ['V-31994', 'SV-42293r3_rule']
end
