control 'SV-17064' do
  title 'Deficient Policy or SOP regarding PC communications video display positioning.'
  desc 'When communicating using a PC based voice, video, UC, or collaboration communications application, the user must protect the information displayed from being viewed by individuals that do not have a need-to-know for the information. This is of additional concern if the information is classified and the viewing party does not have proper clearance. This is also a vulnerability for hardware based communications endpoints that display visual information. The mitigation for this is to position the display such that it cannot be viewed by a passerby.'
  desc 'check', 'Interview the IAO to validate compliance with the following requirement:

Ensure a policy and procedure is in place and enforced that addresses the positioning of video displays associated with communications devices and PC based voice, video, UC, and collaboration communications applications with regard to the sensitivity of the information displayed and the ability of individuals, not part of the communications session, to view the display. Operational policy and procedures must be included in user training and guides.

If video displays associated with communications devices and PC based voice, video, UC, and collaboration communications applications are used to display sensitive or classified information, interview the IAO and inspect the applicable SOP.  The SOP should address the positioning of video displays associated with communications devices and PC based voice, video, UC, and collaboration communications applications with regard to the sensitivity of the information displayed and the ability of individuals, not part of the communications session, to view the display.

Inspect a random sampling of workspaces and conference rooms to determine compliance. Look for displays that are viewable through a window or are viewable from common walkways or areas where non-participants can view the information. The lack of partitions or the use of short partitions separating workspaces can be an issue depending upon the sensitivity of the displayed information.

Inspect user training materials and discuss practices to determine if information regarding the SOP is conveyed. Interview a random sampling of users to confirm their awareness of the SOP and related information.

This is a finding if video displays associated with communications devices and PC based voice, video, UC, and collaboration communications applications that are used to display sensitive or classified information are easily viewable from locations outside the immediate user’s work area. This is also a finding if the SOP or training is deficient.

NOTE: During a SRR, the review of this check may be coordinated with a traditional security reviewer if one is available so that duplication of effort is minimized. However, the similar/related traditional security check primarily addresses displays that are attached to classified systems which are displaying classified information, and not sensitive but unclassified information or privacy information.'
  desc 'fix', 'Ensure a policy and procedure is in place and enforced that addresses the positioning of video displays associated with communications devices and PC based voice, video, UC, and collaboration communications applications with regard to the sensitivity of the information displayed and the ability of individuals, not part of the communications session, to view the display. Operational policy and procedures must be included in user training and guides.

Produce an SOP that addresses the positioning of video displays associated with communications devices and PC based voice, video, UC, and collaboration communications applications with regard to the sensitivity of the information displayed and the ability of individuals, not part of the communications session, to view the display. 

Provide appropriate training such that users follow the SOP. Enforce user compliance with the SOP.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-17120r1_chk'
  tag severity: 'medium'
  tag gid: 'V-16077'
  tag rid: 'SV-17064r1_rule'
  tag stig_id: 'VVoIP/VTC 1910 (GENERAL)'
  tag gtitle: 'Deficient SOP; Video Display Positioning'
  tag fix_id: 'F-16182r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'The inadvertent and/or improper disclosure of sensitive or classified visual information.'
  tag responsibility: ['Information Assurance Officer', 'Information Assurance Manager']
end
