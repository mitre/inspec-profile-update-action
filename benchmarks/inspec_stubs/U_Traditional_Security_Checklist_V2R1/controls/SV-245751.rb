control 'SV-245751' do
  title 'Environmental IA Controls - Humidity'
  desc 'Fluctuations in humidity can be potentially harmful to personnel or equipment causing the loss of services or productivity.

REFERENCES:

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016 Chapter 5, Section 1, paragraph 5-104
                                   
NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls:  PE-14 and PE-14(1) & (2)

NIST SP 800-12, An Introduction to Computer Security: The NIST Handbook

NIST SP 800-100, Information Security Handbook: A Guide for Managers'
  desc 'check', 'Check to see if humidity controls have been installed in all IT areas.  Automatic controls are preferred and should be installed where personnel are not available 24/7 on site to respond to and correct anomalies and situations.  Otherwise it is permissible for alarms to be used when humidity levels fluctuate, requiring manual employee intervention.
  
NOTES:

1. In general such an area will be in raised floor space.  The requirement should not be applied to administrative/office space. This requirement should also not be applied to a tactical environment, unless it is a fixed computer facility supporting missions in a Theater of Operations.  The standards to be applied for applicability in a tactical environment are:  1) The facility containing the computer room has been in operation over 1-year. 2) The facility is "fixed facility" - a hard building made from normal construction materials - wood, steel, brick, stone, mortar, etc.

2. Use of alarms with manual intervention should be supported by specific assessment within the organizational holistic risk assessment.'
  desc 'fix', 'Ensure that humidity controls have been installed in Information Technology (IT) areas (Computer Rooms) to protect personnel and equipment operation, as follows:
  
Automatic controls are preferred and should be installed where personnel are not available 24/7 on site to respond to and correct anomalies and situations.
  
Otherwise it is permissible for alarms to be used when humidity levels fluctuate, requiring manual employee intervention. Adjustments to humidity control systems can be made manually. Note that use of alarms with manual intervention should also be supported by specific assessment within the organizational holistic risk assessment.'
  impact 0.3
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49182r769913_chk'
  tag severity: 'low'
  tag gid: 'V-245751'
  tag rid: 'SV-245751r769915_rule'
  tag stig_id: 'EC-06.03.01'
  tag gtitle: 'EC-06.03.01'
  tag fix_id: 'F-49137r769914_fix'
  tag 'documentable'
  tag legacy: ['V-30990', 'SV-41034r3_rule']
end
