control 'SV-18867' do
  title 'Deficient SOP or enforcement of One Time Use local meeting password'
  desc 'A “local meeting password” must be used one time only. Once any meeting password is distributed to conferees, it is known by them. If a different and unique meeting password is not used for subsequent meetings, someone that has knowledge of (i.e., remembered or recorded) a previously used password could join a conference to which they were not invited to or in which they should not be included. This capability could violate requirements for access to information based on need-to-know and/or could lead to the disclosure of sensitive or classified information. 
     
While the setting of the “local meeting password” password could be an administrator function, most often it is set by the VTU user hosting the conference since the integrated MCU may be used in an ad hoc manner. Ideally, its use would be prescheduled. As noted above, the capability that uses this password should not be functional at all times.
     
Of additional concern is; in the event a local meeting password is not set on the VTU, the VTU might provide no access control to the services that use it. This cannot be permitted if the VTU performs in this manner. As such this issue must be mitigated by configuration of a “blocking” password that is kept confidential. 
     
An additional consideration when using a “meeting password” is that such passwords should be used one time only. Once a meeting password is distributed to conferees, it is known by them. If a different and unique meeting password is not used for subsequent meetings, someone that has knowledge of a previously used password could join a conference that they were not invited to or should not be included. This capability could violate access to information based on need-to-know which could lead to the disclosure of sensitive or classified information.
     
Note: This requirement applies to VTC CODECs that can host a multipoint meeting or conference using an integral MCU. This is typically capable of supporting four to six endpoints. A “local meeting password” typically controls access to the MCU. In some cases, this password is also used to access conference streaming.'
  desc 'check', '[IP][ISDN]; Interview the IAO to validate compliance with the following requirement:

If the use of a local meeting password is required because it is supported by the VTU, ensure a “local meeting password” policy and procedure is in place and enforced along with user training that addresses the following:
- Implementation and distribution of a temporary password for the session when use of the feature is required. This password is used one time and not repeated. This password must not match any other user or administrative password on the device.
- Disablement of the feature when its use is not required or the installation of a strong blocking password that is kept confidential. This password could be distributed as the temporary password when use of the feature is required if it is changed and kept confidential following the session. 
- User instructions on how to properly set and manage the password if site policy permits the user to set the password instead of calling an administrator.
- User awareness training regarding the vulnerabilities associated with the reuse of meeting passwords.

Note:   In some instances, the local meeting password is also used for gaining access to media streamed from the VTU. While these are two different functions or entry points, and should not have the same password, the passwords for these functions are to be managed and used similarly. Streaming is discussed later in this document.

Inspect the SOP as well as user training materials, agreements, and guides to determine if the items in the requirement are adequately covered. Interview the IAO to determine how the SOP is enforced. Interview a sampling of users to determine their awareness and implementation of the requirement and whether the SOP is enforced. This is a finding if deficiencies are found in any of these areas. Note the deficiencies in the finding details.

Note: This requirement applies to VTC CODECs that can host a multipoint meeting or conference using an integral MCU. This is typically capable of supporting four to six endpoints. A “local meeting password” typically controls access to the MCU. In some cases, this password is also used to access conference streaming.

Note: This requirement applies to VTU CODECs that contain an integrated MCU 


Note: During APL testing, this is a finding in the event one time “meeting passwords” are not supported by the MCU.'
  desc 'fix', '[IP][ISDN]; Perform the following tasks:
Define and enforce policy and procedure that addresses the management and use of a “local meeting password” for access to meetings hosted or streamed by a CODEC. The SOP will include the following:
- Implementation and distribution of a temporary password for the session when use of the feature is required. This password is used one time and not repeated. This password must not match any other user or administrative password on the device.
- Disablement of the feature when its use is not required or the installation of a strong blocking password that is kept confidential. This password could be distributed as the temporary password when use of the feature is required if it is changed and kept confidential following the session. 
- User instructions on how to properly set and manage the password if site policy permits the user to set the password instead of calling an administrator.
- User awareness training regarding the vulnerabilities associated with the reuse of meeting passwords.

Provide user training regarding the SOP and include it in user agreements and user guides.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18963r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17693'
  tag rid: 'SV-18867r1_rule'
  tag stig_id: 'RTS-VTC 2320.00'
  tag gtitle: 'RTS-VTC 2320.00 [IP][ISDN]'
  tag fix_id: 'F-17590r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'The inadvertent disclosure of sensitive or classified information to a caller of a VTU that may not have an appropriate need-to-know or proper security clearance.'
  tag responsibility: ['Information Assurance Officer', 'Information Assurance Manager']
end
