control 'SV-17061' do
  title 'Deficient Policy or SOP for VTC and PC camera operations regarding their ability to pickup and transmit sensitive or classified information in visual form.'
  desc 'Users of conference room or office based VTC systems and PC based communications applications that employ a camera must not inadvertently display information of a sensitive or classified nature that is not part of the communications session while the camera is active. This can happen if information in the form of charts, pictures, or maps are displayed on a wall within the viewing, or capture range of a camera. Any Pan, Tilt, and Zoom (PTZ) capabilities of the camera must be considered. One may consider visual information out of range, but it may be in range considering camera capabilities such as high definition, PTZ, and video enhancement possibilities for captured frames. Inadvertent display of classified information could also happen if the information is laying on a desk or table unprotected.

NOTE: Vulnerability awareness and operational training will be provided to users of VTC and video/collaboration communications related camera(s) regarding these requirements.

NOTE: This requirement is relevant no matter what the classification level of the session. In an IP environment the classification of VTC or PC communications is dependent upon the classification of the network to which the VTU or PC is attached and the classification of the facility in which it is located. While classified communications can occur at the same level of classification as the network and facility, communications having a lower classification or no classification (e.g., unclassified or FOUO) may also occur in the same environment. As such, sensitive or classified information that is not part of the communications session might be improperly disclosed without proper controls in place.'
  desc 'check', 'Interview the IAO to validate compliance with the following requirement:

Ensure a policy and procedure is in place and enforced that addresses the operation of video/collaboration communications related cameras (e.g., webcams or VTC cameras) regarding their ability to inadvertently capture and transmit sensitive or classified information such that: 
- Conference room and office users do not display sensitive or classified information on walls that are within the view of the camera(s).
- Conference room and office users do not place sensitive or classified information on a table or desk within the view of the camera(s) without proper protection (e.g., a proper cover).
- Conference room and office users do not read or view sensitive or classified information at such an angle that the camera(s) could focus on it. 


NOTE: While covering such information mitigates disclosure when a camera is to be used, if the camera is activated unexpectedly or without taking action to cover the information prior to activating, the information can be compromised. The best practice is to not display it in view of the camera at all.

NOTE: Vulnerability awareness and operational training will be provided to users of video/collaboration communications related camera(s) regarding these requirements.

NOTE: This requirement is relevant no matter what the classification level of the session. In an IP environment the classification of PC communications is dependent upon the classification of the network to which the PC is attached, and the classification of the facility in which it is located. While classified communications can occur at the same level of classification as the network and facility, communications having a lower classification or no classification (e.g., unclassified or FOUO) may also occur in the same environment. As such, sensitive or classified information that is not part of the communications session might be improperly disclosed without proper controls in place.
Inspect the applicable SOP. 

Inspect a random sampling of workspaces and conference rooms to determine compliance. Look for potentially sensitive information posted on the walls in view of the camera(s). 

Interview the IAO to determine how the SOP is enforced. Inspect user training materials and discuss practices to determine if information regarding the SOP is conveyed. Interview a random sampling of users to confirm their awareness of the SOP and related information.

This is a finding if deficiencies are found in any of these areas. Note the deficiencies in the finding details.'
  desc 'fix', 'Ensure a policy and procedure is in place and enforced that addresses the operation of video/collaboration communications related cameras (e.g., webcams or VTC cameras) regarding their ability to inadvertently capture and transmit sensitive or classified information. 

Do not post potentially sensitive information posted on the walls in view of the camera(s).

Produce an SOP that addresses  the operation of video/collaboration communications related cameras (e.g., webcams or VTC cameras) regarding their ability to inadvertently capture and transmit sensitive or classified information such that: 
- Conference room and office users do not display sensitive or classified information on walls that are within the view of the camera(s).
- Conference room and office users do not place sensitive or classified information on a table or desk within the view of the camera(s) without proper protection. (e.g., a proper cover).
- Conference room and office users do not read or view sensitive or classified information at such an angle that the camera(s) could focus on it. 

NOTE: while covering such information mitigates disclosure when a camera is to be used, if the camera is activated unexpectedly or without taking action to cover the information prior to activating, the information can be compromised. Best practice is to not display it in view of the camera at all.

Provide appropriate training such that users follow the SOP. Enforce user compliance with the SOP.'
  impact 0.7
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-17117r3_chk'
  tag severity: 'high'
  tag gid: 'V-16074'
  tag rid: 'SV-17061r2_rule'
  tag stig_id: 'VVoIP/VTC 1900 (GENERAL)'
  tag gtitle: 'Deficient SOP: Camera operations / pickup'
  tag fix_id: 'F-16179r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag responsibility: ['Information Assurance Manager', 'Information Assurance Officer']
  tag ia_controls: 'DCBP-1, ECND-1, ECSC-1'
end
