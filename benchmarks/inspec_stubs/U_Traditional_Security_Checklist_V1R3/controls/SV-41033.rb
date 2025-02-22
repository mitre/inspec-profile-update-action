control 'SV-41033' do
  title 'Environmental IA Controls - Temperature'
  desc 'Lack of temperature controls can lead to fluctuations in temperature which could be potentially harmful to personnel or equipment operation.

REFERENCES:

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016 Chapter 5, Section 1, paragraph 5-104
                       
NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls:  PE-14 and PE-14(1) & (2)

NIST SP 800-12, An Introduction to Computer Security: The NIST Handbook

NIST SP 800-100, Information Security Handbook: A Guide for Managers'
  desc 'check', 'Check to see if temperature controls have been installed.  Automatic controls are preferred and should be installed where personnel are not available 24/7 on site to respond to and correct anomalies and situations. Otherwise it is permissible for alarms to be used when temperatures fluctuate, requiring manual employee intervention.  

NOTES: 
 
1. In general such an area will be in raised floor space.  The requirement should not be applied to administrative/office space. This requirement should also not be applied to a tactical environment, unless it is a fixed computer facility supporting missions in a Theater of Operations. The standards to be applied for applicability in a tactical environment are:  1) The facility containing the computer room has been in operation over 1-year. 2) The facility is "fixed facility" - a hard building made from normal construction materials - wood, steel, brick, stone, mortar, etc.

2. Use of alarms with manual intervention should be supported by specific assessment within the organizational holistic risk assessment.'
  desc 'fix', 'Ensure that temperature controls have been installed as follows: 
 
Automatic controls are preferred and should be installed where personnel are not available 24/7 on site to respond to and correct anomalies and situations.
  
Otherwise it is permissible for alarms to be used when temperatures fluctuate, requiring manual employee intervention. Note that use of alarms with manual intervention should also be supported by specific assessment within the organizational holistic risk assessment.'
  impact 0.3
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-39654r5_chk'
  tag severity: 'low'
  tag gid: 'V-30989'
  tag rid: 'SV-41033r3_rule'
  tag stig_id: 'EC-05.03.01'
  tag gtitle: 'Environmental IA Controls - Temperature'
  tag fix_id: 'F-34799r5_fix'
  tag 'documentable'
end
