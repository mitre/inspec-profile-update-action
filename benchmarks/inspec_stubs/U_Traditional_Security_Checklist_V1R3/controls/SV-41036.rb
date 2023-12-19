control 'SV-41036' do
  title 'Environmental IA Controls - Fire Inspections/ Discrepancies'
  desc 'Failure to conduct fire inspections and correct any discrepancies could result in hazardous situations leading to a possible fire and loss of service.

REFERENCES:

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016 Chapter 5, Section 1, paragraph 5-104    
                               
NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls:  PE-13(4)

NIST SP 800-12, An Introduction to Computer Security: The NIST Handbook

NIST SP 800-100, Information Security Handbook: A Guide for Managers'
  desc 'check', 'Check fire marshal inspection reports and documentation that verifies discrepancies are addressed and corrected.

Inspections must be conducted on at least an annual basis.

NOTES:

1. In general this should be applied to major IT equipment areas (generally computer rooms with raised floor space containing servers and communications equipment). The requirement should not be applied to administrative/office space. 
  
2. Also, this requirement should not be applied to a tactical environment, unless it is a fixed computer facility supporting missions in a Theater of Operations.  The standards to be applied for applicability in a tactical environment are: 1) The facility containing the computer room has been in operation over 1-year. 2) The facility is "fixed facility" - a hard building made from normal construction materials - wood, steel, brick, stone, mortar, etc.

3. Even if there is no finding the reviewer should note in the report the date the last fire marshal or similar inspection was conducted with a summary of results. This information could be useful during subsequent inspections.'
  desc 'fix', 'Periodic fire marshal inspections of (IT) computing facilities must be conducted (minimum annually) and   discrepancies noted during the inspections must be promptly addressed.'
  impact 0.3
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-39656r6_chk'
  tag severity: 'low'
  tag gid: 'V-30991'
  tag rid: 'SV-41036r3_rule'
  tag stig_id: 'EC-07.03.01'
  tag gtitle: 'Environmental IA Controls - Fire Inspections/ Discrepancies'
  tag fix_id: 'F-34802r4_fix'
  tag 'documentable'
end
