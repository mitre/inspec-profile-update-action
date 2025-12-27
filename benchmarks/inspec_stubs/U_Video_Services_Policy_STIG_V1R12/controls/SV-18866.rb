control 'SV-18866' do
  title 'Deficient SOP or enforcement of the SOP for manual password management.'
  desc 'DoD password and account management policies and requirements that are not supported by the CODEC must be addressed and enforced by a site policy or SOP that provides compliance to the greatest extent possible within the capabilities of the system/device. Typically a CODEC supports only one administrative password and therefore a group administrator account/password must be used. Some CODECs can support multiple user passwords or PINs for accounting purposes. Additionally, there are other passwords used to access certain features of the system and for the system and user to access other systems and devices.'
  desc 'check', '[IP][ISDN]; Interview the IAO to validate compliance with the following requirement:

In the event a system/device does not support all DoD IA requirements for password/PIN and account management or logon requirements, ensure a policy and procedure is in place and enforced that minimally addresses the following:
- Strong passwords/PINs will be used to the extent supported by the system/device. Each access point and  
  password will be addressed separately. 
- Password/PIN reuse will be limited and will be in compliance with policy and INFOCON requirements
- Password/PIN change intervals will be defined for each access point based upon policy, INFOCON levels, and 
  operational requirements.
- Passwords/PINs will be changed when compromised or personnel (users or administrators) leave the organization. 
- Passwords/PINs that are no longer needed will be removed in a timely manner. A periodic review will be performed 
  as scheduled by the SOP.
- SNMP community strings will be managed like passwords/PINs. 
- A password/PIN change/removal log will be maintained and stored in a secure access controlled manner (such as in a safe or encrypted file on an access controlled server of workstation) for each device noting each access point, its password, and the date the password was changed. Such a log will aid in such things as SOP enforcement, password history compliance, and password recovery.

Note: If and when VTC systems provide support for user and administrator accounts, this SOP is extended or modified to cover account management as necessary to manage non-automated functions. 

Inspect the SOP as well as user training materials, agreements, and guides to determine if the items in the requirement are adequately covered. Interview the IAO to determine how the SOP is enforced. Interview a sampling of users to determine their awareness and implementation of the requirement and whether the SOP is enforced. This is a finding if deficiencies are found in any of these areas. Note the deficiencies in the finding details.'
  desc 'fix', '[IP][ISDN];  Perform the following tasks:
Define and enforce policy and procedure that addresses password/PIN and account management that includes the following:
- Strong passwords/PINs will be used to the extent supported by the system/device. Each access point and  
  password will be addressed separately. 
- Password/PIN reuse will be limited and will be in compliance with policy and INFOCON requirements.
- Password/PIN change intervals will be defined for each access point based upon policy, INFOCON levels, and 
  operational requirements.
- Passwords/PINs will be changed when compromised or personnel (users or administrators) leave the organization. 
- Passwords/PINs that are no longer needed will be removed in a timely manner. A periodic review will be performed as scheduled by the SOP.
- SNMP community strings will be managed like passwords/PINs. 
- A password/PIN change/removal log will be maintained and stored in a secure access controlled manner (such as in a safe or encrypted file on an access controlled server of workstation) for each device noting each access point, its password, and the date the password was changed. Such a log will aid in such things as SOP enforcement, password history compliance, and password recovery.

Provide user training regarding this SOP and include it in user agreements and user guides.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18962r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17692'
  tag rid: 'SV-18866r1_rule'
  tag stig_id: 'RTS-VTC 2040.00'
  tag gtitle: 'RTS-VTC 2040.00 [IP][ISDN]'
  tag fix_id: 'F-17589r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'Access to the VTU by unauthorized individuals possibly leading to the disclosure of sensitive or classified information to a caller of a VTU that may not have an appropriate need-to-know or proper security clearance.'
  tag responsibility: ['Information Assurance Officer', 'Information Assurance Manager']
  tag ia_controls: 'DCBP-1, ECSC-1, IAAC-1, IAGA-1, IAIA-1, IAIA-2'
end
