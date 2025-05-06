control 'SV-245748' do
  title 'Environmental IA Controls - Emergency Power'
  desc 'Failure to have alternative power sources available can result in significant impact to mission accomplishment and information technology systems including potential loss of data and damage to the IT equipment during a commercial power service outage.

REFERENCES:

DoD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016 Chapter 5, Section 1, paragraph 5-104 
                                 
NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: PE-11 and PE-11(1) & (2)

NIST SP 800-12, An Introduction to Computer Security: The NIST Handbook

NIST SP 800-100, Information Security Handbook: A Guide for Managers'
  desc 'check', 'Check that alternate sources of power are available for key IT system assets.  Specifically check that both of the following requirements are complied with:

A short-term uninterruptible power supply is available to facilitate an orderly shutdown of the information system and transition of the information system to longer-term alternate power (if available) in the event of a primary power source loss. (CAT II)

The need for additional short term or long term alternative power sources such as use of a secondary commercial power supply or use of one or more generators with sufficient capacity to meet the needs of the organization have been considered in the organizations Holistic Risk Assessment; when such alternative sources of power are not available.  (CAT III)

NOTES:
   
1.  In general rule application will be for major computing centers with raised floor space.  The requirement should not be applied to administrative/office space. This requirement should also not be applied to a tactical environment, unless it is a fixed computer facility supporting missions in a Theater of Operations.  The standards to be applied for applicability in a tactical environment are:  1) The facility containing the computer room has been in operation over 1-year. 2) The facility is "fixed facility" - a hard building made from normal construction materials - wood, steel, brick, stone, mortar, etc.

2.  It is not necessary for the risk assessment to specifically address the need for long term alternative power if it is actually available at the site.'
  desc 'fix', 'A short-term uninterruptible power supply must be installed to facilitate an orderly shutdown of the information system and transition of the information system to longer-term alternate power (if available) in the event of a primary power source loss.
 
Additionally, the need for additional short term or long term alternative power sources such as use of a secondary commercial power supply or use of one or more generators with sufficient capacity to meet the needs of the organization must be considered in the organizations Holistic Risk Assessment; when such alternative sources of power are actually not available.'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49179r769904_chk'
  tag severity: 'medium'
  tag gid: 'V-245748'
  tag rid: 'SV-245748r822815_rule'
  tag stig_id: 'EC-03.03.02'
  tag gtitle: 'EC-03.03.02'
  tag fix_id: 'F-49134r769905_fix'
  tag 'documentable'
  tag legacy: ['V-61629', 'SV-76119r1_rule']
end
