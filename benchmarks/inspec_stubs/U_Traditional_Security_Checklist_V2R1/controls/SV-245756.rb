control 'SV-245756' do
  title 'TEMPEST - Red/Black Separation (Cables)'
  desc 'Failure to maintain proper separation could result in detectable emanations of classified information.

REFERENCES:
                                 
CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND)

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 11 

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: PE-19 & PE-19(1)

Committee on National Security Systems Policy 300, "National Policy on Control of Compromising Emanations," April 2004, as amended 
                             
Committee on National Security Systems Instruction 7000, "TEMPEST Countermeasures for Facilities," May 2004, as amended   
                           
DoDI 8500.01, SUBJECT: Cybersecurity, March 14, 2014 
                                   
CNSSAM TEMPEST/ 1-13, 17 January 2014, RED/BLACK Installation Guidance'
  desc 'check', 'Check that unless separated by a metal distribution system such as conduit or enclosed cable tray, a minimum separation distance of 5 cm (2 inches) or (15 cm (6 inches) for parallel cable lengths over 30 meters (98.4 feet)) is provided between any RED wire line and BLACK wire lines that exit the inspectable space or are connected to an RF transmitter, or BLACK power lines, or a digital switch (such as a computerized telephone switch or network router) that is contained within the inspectable space.

NOTES: 

1. This requirement is applicable in a tactical environment.
  
2. The supporting CTTA should always be contacted for specific separation requirements, which may be greater than the distance reflected in this check.

3. Inspectable Space is the three dimensional space surrounding equipment that processes classified and/or sensitive information within which TEMPEST exploitation is not considered practical or where legal authority to identify and remove a potential TEMPEST exploitation exists and is exercised. CTTAs have the authority to define the inspectable space.'
  desc 'fix', 'Unless separated by a metal distribution system such as conduit or enclosed cable tray, a minimum separation distance of 5 cm (2 inches) or ( 15 cm (6 inches) for parallel cable lengths over 30 meters (98.4 feet)) shall be provided between any RED wire line and BLACK wire lines that exit the inspectable space or are connected to an RF transmitter, or BLACK power lines, or a digital switch (such as a computerized telephone switch or network router) that is contained within the inspectable space.

NOTES: 

1. This requirement is applicable in a tactical environment. 
 
2. The supporting CTTA should always be contacted for specific separation requirements, which may be greater than the distance reflected in this check.

3. Inspectable Space is the three dimensional space surrounding equipment that processes classified and/or sensitive information within which TEMPEST exploitation is not considered practical or where legal authority to identify and remove a potential TEMPEST exploitation exists and is exercised. CTTAs have the authority to define the inspectable space.'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49187r769928_chk'
  tag severity: 'medium'
  tag gid: 'V-245756'
  tag rid: 'SV-245756r769930_rule'
  tag stig_id: 'EM-03.02.01'
  tag gtitle: 'EM-03.02.01'
  tag fix_id: 'F-49142r769929_fix'
  tag 'documentable'
  tag legacy: ['V-30982', 'SV-41026r3_rule']
end
