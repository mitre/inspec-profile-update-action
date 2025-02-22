control 'SV-245753' do
  title 'Environmental IA Controls - Fire Detection and Suppression'
  desc 'Failure to provide adequate fire detection and suppression could result in the loss of or damage to data, equipment, facilities, or personnel.

REFERENCES:

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016 Chapter 5, Section 1, paragraph 5-104 
                                  
NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: PE-13 and PE-13(1), (2), (3) and (4)

NIST SP 800-12, An Introduction to Computer Security: The NIST Handbook

NIST SP 800-100, Information Security Handbook: A Guide for Managers'
  desc 'check', '1. Check to ensure a fully automatic fire detection and suppression system is installed for information system areas that automatically activates when it detects heat, smoke, or particles. 

2. Check that a servicing fire department receives an automatic notification of any activation of the smoke detection or fire suppression system.
 
3. Check for periodic fire detection and suppression test logs. 

4. Check the fire detection and suppression system(s) are supported by an independent or alternate (backup) energy source.

NOTES: This check applies primarily to facilities containing concentrations of information system resources including, for example, data centers, server rooms, and mainframe computer rooms. Fire suppression and detection devices/systems include, for example, sprinkler systems, handheld fire extinguishers, fixed fire hoses, and smoke detectors.'
  desc 'fix', 'An adequate fire detection and suppression system must be installed and must be periodically tested. The following considerations must be incorporated into the system:

1. A fully automatic fire detection and suppression system must be installed for information system areas that automatically activates when it detects heat, smoke, or particles.
 
2. A servicing fire department must receive an automatic notification of any activation of the smoke detection or fire suppression system.
 
3. Periodic testing of the fire detection and suppression system must be conducted.
 
4. The fire detection and suppression system(s) must be supported by an independent or alternate (backup) energy source.'
  impact 0.3
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49184r769919_chk'
  tag severity: 'low'
  tag gid: 'V-245753'
  tag rid: 'SV-245753r769921_rule'
  tag stig_id: 'EC-08.03.01'
  tag gtitle: 'EC-08.03.01'
  tag fix_id: 'F-49139r769920_fix'
  tag 'documentable'
  tag legacy: ['V-30992', 'SV-41037r3_rule']
end
