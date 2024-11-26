control 'SV-18722' do
  title 'Auto-answer feature is not administratively disabled.'
  desc 'Some VTC endpoints have a user selectable feature that provides the capability to automatically answer an incoming call. This would be akin to your speakerphone picking up a call each time the phone rang allowing an ongoing conversation to be heard by the caller. This feature, if activated, is highly detrimental to the confidentiality of information in a room in which a VTU is installed. In fact, a security incident could result from “auto-answer” being enabled. Such would be the case in the event a VTU automatically answered a call when a classified meeting or discussion (not via VTC) was being held in a conference room or an office having VTC capability. The auto-answer feature must not be activated by a user unless the feature is required to satisfy mission requirements. Furthermore, users must be trained in the vulnerabilities associated with the auto-answer feature and in its proper use if it is to be used.  The ideal mitigation for this vulnerability is for the auto-answer feature to not be supported by the VTU or there be an administrator setting that can disable the feature preventing a user from activating it.'
  desc 'check', '[IP][ISDN];  Interview the IAO to validate compliance with the following requirement:

If a VTC endpoint auto-answer feature is available, ensure it is administratively disabled, thus ensuring the feature is not selectable by the user, unless required to satisfy validated, approved, and documented mission requirements. 
Note: The documented and validated mission requirements along with their approval(s) are maintained by the IAO for inspection by auditors. Such approval will be obtained from the DAA or IAM responsible for the VTU(s) or system.
Note: During APL testing, this is a finding in the event this requirement is not supported by the VTU.

Verify that if the auto-answer feature is available on the VTU endpoint that it is administratively disabled.  If the auto-answer is a mission requirement, verify that IAO has evidence/documentation that the DAA or IAM responsible has given written approval for its use.'
  desc 'fix', '[IP][ISDN]; Perform the following tasks:
Administratively disable the auto-answer function on the VTU unless required to fulfill validated and approved mission requirements.

If auto-answer is required to fulfill validated and approved mission requirements, obtain written approval for the use of this function from DAA or IAM and maintain documentation on the validated requirement and approval.
Train users in the proper use and vulnerabilities associated with the use of auto-answer'
  impact 0.3
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18895r1_chk'
  tag severity: 'low'
  tag gid: 'V-17595'
  tag rid: 'SV-18722r1_rule'
  tag stig_id: 'RTS-VTC 1040.00'
  tag gtitle: 'RTS-VTC 1040.00 [IP][ISDN]'
  tag fix_id: 'F-17513r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'The inadvertent disclosure of sensitive or classified information to a caller of a VTU that may not have an appropriate need-to-know or proper security clearance.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', 'Designated Approving Authority', 'Other']
  tag ia_controls: 'DCBP-1, ECSC-1'
end
