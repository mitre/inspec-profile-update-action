control 'SV-18893' do
  title 'Access control measures must be implemented for all conferences hosted on a centralized MCU appliance.'
  desc 'Access control must be exercised over participants joining multipoint conferences. Attendees and endpoints must be authorized or registered in advance. This way the conference organizers can control who has access to sensitive or classified information based upon validated clearance and need-to-know. Unrestricted access or the use of a meeting password that is reused or well-known can lead to a security incident where information is improperly disclosed to unauthorized individuals not having appropriate clearance or need-to-know. Additionally, if call-in access is supported and approved, a one-time use meeting password is required. 

H.323 gatekeepers provide access control for VTC network infrastructure devices such as MCUs and gateways to VTC endpoints. Using H.225 an endpoint can discover a gatekeeper and register with it. The endpoint is identified by the gatekeeper by a “gatekeeper password” which is essentially the endpoint ID. The gatekeeper provides address translation and bandwidth management. Once registered with the gatekeeper an endpoint must ask permission of the gatekeeper to make a call. If the available VTC bandwidth is used or limited, the gatekeeper can reject the request or negotiate a lower bandwidth. This acts as part of the access control mechanism for the MCU and works in combination with a scheduling application. The rest of the MCU access control equation is pre-registration of the endpoint IDs when scheduling a conference. Pre-registration of endpoint IDs for specific conferences is required because there are typically no meeting passwords and the phone numbers or IP addresses of the MCU ports don’t change between sessions. Additionally (and here’s the issue mentioned above) people are not authenticated only endpoints are. The endpoint ID is critical in this access control process. The endpoint ID is entered (pre-configured) in the system for a specific scheduled conference. The system only permits the endpoint to access the MCU during the scheduled time of the conference. 

This discussion also applies to ad hoc conferences and “standing” conferences. A standing conference is one where MCU facilities are dedicated to a conference that is operational all of the time or one that is regularly scheduled to be operational for certain time periods. The implementation of a standing conference permits conferees to join the conference at will or as needed to discuss a current topic or mission. Standing conferences are implemented for many reasons. Standing conferences are more vulnerable to compromise than one time scheduled events. Extra care must be exercised regarding access control to these conferences.'
  desc 'check', 'Review site documentation to confirm control measures are implemented for all conferences hosted on a centralized MCU appliance as follows: 
- Only authorized endpoints are permitted to access an MCU
- Only authorized users are permitted to access/join a conference. Authorization is pre-configured on the MCU access control system and is based on validated need-to-know as well as security clearance if applicable.

If access control measures are not implemented for all conferences hosted on a centralized MCU appliance, this is a finding.'
  desc 'fix', 'Implement access control measures for all conferences hosted on a centralized MCU appliance as follows: 
- Only authorized endpoints are permitted to access an MCU
- Only authorized users are permitted to access/join a conference. Authorization is pre-configured on the MCU access control system and is based on validated need-to-know as well as security clearance if applicable.

Note: this applies to standing, scheduled one-time, and non-scheduled ad hoc conferences.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18989r3_chk'
  tag severity: 'medium'
  tag gid: 'V-17719'
  tag rid: 'SV-18893r2_rule'
  tag stig_id: 'RTS-VTC 5020.00'
  tag gtitle: 'RTS-VTC 5020'
  tag fix_id: 'F-17616r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', 'Other']
end
