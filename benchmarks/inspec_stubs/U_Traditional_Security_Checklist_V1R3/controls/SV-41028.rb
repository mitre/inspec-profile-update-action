control 'SV-41028' do
  title 'Environmental IA Controls - Emergency Lighting and Exits - Properly Installed'
  desc 'Lack of automatic emergency lighting and exits can cause injury and/or death to employees and emergency responders. Lack of automatic emergency lighting can also cause a disruption in service.

REFERENCES:

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016 Chapter 5, Section 1, paragraph 5-104  
            
NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls:  PE-12 and PE-12(1)

NIST SP 800-12, An Introduction to Computer Security: The NIST Handbook

NIST SP 800-100 Information Security Handbook: A Guide for Managers'
  desc 'check', 'Check that emergency lighting and exits are located in IT areas.  

NOTES: This requirement should not be applied to a tactical environment, unless it is a fixed computer facility supporting missions in a Theater of Operations.

The standards to be considered for applicability in a tactical environment are:  

1) The facility containing the computer room has been in operation over one year. 

2) The facility is "fixed facility" - a hard building made from normal construction materials - wood, steel, brick, stone, mortar, etc.'
  desc 'fix', 'Emergency lighting and exit signage must be installed in areas containing information systems.'
  impact 0.5
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-39649r8_chk'
  tag severity: 'medium'
  tag gid: 'V-30984'
  tag rid: 'SV-41028r3_rule'
  tag stig_id: 'EC-02.02.01'
  tag gtitle: 'Environmental IA Controls - Emergency Lighting and Exits - Properly Installed'
  tag fix_id: 'F-34795r5_fix'
  tag 'documentable'
end
