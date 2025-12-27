control 'SV-55769' do
  title 'An ISDN-based or IP-based VTC system supporting conferences on multiple networks having different classification levels must utilize approved automatically controlled signage to indicate the secure/non-secure status or classification level of the conference/session. Such signage will be placed within the conference room and outside each entrance.'
  desc 'VTC system users within the room must be informed when the system is actively engaged in a classified session and the classification level of that session if multiple classification levels are supported by the system. This will inform the participants regarding the information they may discuss during the session, thus preventing information having higher classification being discussed in a session having a lower classification level. Additionally, persons entering a room where classified VTC sessions occur must be informed of the status and classification level of the session so that persons without the appropriate clearance level for the information being discussed/presented do not enter the room. Both situations can lead to improper disclosure of classified information.
System signage must minimally reflect secure/non-secure status of the system. The signage in IP-based systems connected to multiple classified networks must additionally reflect the classification of the network to which the system is connected. Signage must be controlled by the A/B, A/B/C, or A/B/C/D switch position.'
  desc 'check', 'Inspect the room where conferences take place to observe sign placement and that they accurately reflect the secure/non-secure status or classification of the network to which the system is connected. This will require a demonstration of the capability.  If the signage is not posted or it does not accurately reflect the secure/non-secure status or classification of the network to which the system is connected, this is a finding.'
  desc 'fix', 'Obtain and implement approved automatically controlled signage that indicates the secure/non-secure status or classification level of the conference/session. Install signs so they are clearly visible within the room and at the entranceways.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-49189r3_chk'
  tag severity: 'medium'
  tag gid: 'V-43040'
  tag rid: 'SV-55769r1_rule'
  tag stig_id: 'RTS-VTC 7340'
  tag gtitle: 'RTS-VTC 7340 [IP] [ISDN]'
  tag fix_id: 'F-48620r3_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'PEPF-1'
end
