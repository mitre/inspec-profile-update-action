control 'SV-14818' do
  title 'WMAN systems must require strong authentication from the user or WMAN subscriber device to WMAN network.'
  desc 'Broadband systems not compliant with authentication requirements could allow a hacker to gain access to the DoD network.'
  desc 'check', 'Detailed Policy Requirements:

The site WMAN systems will implement strong authentication from the User or WMAN subscriber device to WMAN network.  For tactical WMAN systems or commercial WMAN systems operated in a tactical environment, two factor authentication is required, at a minimum.  

Note:  Examples of two-factor authentication are password with biometrics or CAC with PIN.

In cases where there are no available WMAN technology solutions that meets this requirement, the local DAA may grant an exception to this requirement until such time as a WMAN product is available that meets this requirement. The exception must be documented during the system DIACAP and in the site SSAA/SSP.  At a minimum, the system must meet the authentication requirements of non-tactical WMAN systems.

-For tactical or commercial WMAN systems operated in a non-tactical environment, this check does not apply:  Checks WIR0315-02 and WIR0315-02 apply.    

Check Procedures:

-  Determine if the WMAN system is used in a tactical or non-tactical environment.
- Review the WMAN system product documentation  (specification sheet, network administration manual, installation manual, etc.) to determine what authentication mechanism is supported between the user/subscriber device and WMAN network. 
- Review the authentication configuration configured on the WMAN access point.  (Have the system administrator and user show you the setting.)  
- Verify “User or WMAN subscriber device to WMAN network” authentication meets requirements.
 --For WMAN systems operated in a tactical environment, two factor authentication is required, at a minimum, unless the DAA has approved an exception based on the unavailability of a WMAN product that meets this requirement.  Determine if two factor authentication is used (e.g. CAC) or if the DAA has granted an exception.  If the DAA has granted an exception, verify the exception has been noted in the site’s SSAA/SSP and that the system meets the requirements for non-tactical authentication.

-Mark as a finding if the authentication requirements are not met.'
  desc 'fix', 'Implement strong authentication for the user or device to the WMAN network.'
  impact 0.5
  ref 'DPMS Target Wireless Client'
  tag check_id: 'C-22269r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14207'
  tag rid: 'SV-14818r1_rule'
  tag stig_id: 'WIR0315-01'
  tag gtitle: 'WMAN authentication - Subscriber to Network'
  tag fix_id: 'F-34138r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECSC-1, ECWN-1'
end
