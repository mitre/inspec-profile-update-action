control 'SV-93757' do
  title 'Video conferencing, Unified Capability (UC) soft client, and speakerphone speaker operations policy must prevent disclosure of sensitive or classified information over non-secure systems.'
  desc 'Speakers used with Voice Video systems and devices may be heard by people and microphones with no relationship to the conference or call in progress. In open areas, conference audio may be overheard by others in the area without a need-to-know. 

A policy must be in place and enforced regarding the placement and use of speakers connected to secure Voice Video systems (video conferencing, EVoIP, ECVoIP, etc.) and secure Voice Video endpoints (STU-III, STE, etc.) located in areas or rooms where classified meetings, conversations, or work normally occur. The policy must be in accordance with NSA and DCI guidance and address, at a minimum, the following:
- Location if instruments must be limited to sole-use offices, conference rooms, and similar areas that afford sound attenuation.
- Notification to all room occupants of the use of the speaker.
- Notification to all room occupants for awareness of the classification of conversations taking place.
- The room occupant assuming responsibility for taking the necessary precautions to ensure that the classified discussion is not overheard.
- Secure Voice Video endpoints must be configured to prevent speaker enablement in the non-secure mode.

Speakerphone use on secure telecommunications systems requires special consideration regarding placement and operating policy. NSA S412 approves the installation/enablement of speakerphones on National Secure Telephone Systems (NSTS) and STU-III/STE instruments. The intent of speakerphone approval rests with the room occupant assuming responsibility for taking the necessary precautions to ensure that the classified discussion is not overheard by individuals outside the conversation who may not have a need-to-know for the information discussed and/or that the speakerphone will not pick up and transmit other classified conversations in the area that are not part of the call in progress.'
  desc 'check', 'Confirm a policy and supporting procedures are in place that address the placement and operation of video conferencing, UC soft client, and speakerphone speakers to prevent disclosure of sensitive or classified information over non-secure systems. Operational policy and procedures are included in user training and guides. 

The policy and supporting procedures should take into account the classification of the area where the video conferencing equipment, the PC supporting a UC soft client, and Voice Video endpoints are placed, as well as the classification and need-to-know restraints of the information communicated within the area. Include measures such as closing office or conference room doors, adjusting volume levels in open offices, and muting microphones when not directly in use.

If a policy and supporting procedures governing video conferencing, UC soft client, and speakerphone speaker operations preventing disclosure of sensitive or classified information over non-secure systems do not exist or are not enforced, this is a finding.'
  desc 'fix', 'Document and enforce a policy and procedure for video conferencing, UC soft client, and speakerphone speaker operations to prevent disclosure of sensitive or classified information over non-secure systems. Ensure appropriate training is provided for users.

The policy and supporting procedures should take into account the classification of the area where the video conferencing equipment, the PC supporting a UC soft client, and Voice Video endpoints are placed, as well as the classification and need-to-know restraints of the information communicated within the area. Include measures such as closing office or conference room doors, adjusting volume levels in open offices, and muting microphones when not directly in use.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-78639r1_chk'
  tag severity: 'medium'
  tag gid: 'V-79051'
  tag rid: 'SV-93757r2_rule'
  tag stig_id: 'VVT/VTC 1906'
  tag gtitle: 'Speaker operations policy'
  tag fix_id: 'F-85801r1_fix'
  tag 'documentable'
end
