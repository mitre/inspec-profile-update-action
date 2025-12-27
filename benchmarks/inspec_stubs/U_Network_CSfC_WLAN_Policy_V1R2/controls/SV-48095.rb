control 'SV-48095' do
  title 'If Commercial Mobile Devices (CMD) (smartphones or tablets) are used as clients in the campus WLAN system, DoD CIO Memorandum, Use of Commercial Mobile Device (CMD) in the Department of Defense (DoD) must be followed.'
  desc 'DoD CIO Memorandum, “Use of Commercial Mobile Device (CMD) in the Department of Defense (DoD)”, 6 Apr 2011, requires specific security controls be implemented in the DoD because these technologies “adds a new element of risk to DoD information”. Classified DoD networks and/or data could be exposed if required controls are not implemented for CMDs that operate as components of a campus WLAN system that is based on the CSfC Campus IEEE 802.11 Wireless Local Area Network (WLAN) Capability Package.'
  desc 'check', 'Interview the IAM and/or the IAO. Determine if CMDs are used as components of the campus WLAN system that is based on the CSfC Campus IEEE 802.11 Wireless Local Area Network (WLAN) Capability Package. If yes, verify the following key requirements in the DoD CIO memo have been implemented:

-The CMDs are managed and controlled by an enterprise management system (Mobile Device Management (MDM) server).
-Software and applications must be installed from an approved source (e.g., DoD application store).

If CMDs are used as components of the campus WLAN system that is based on the Campus IEEE 802.11 Wireless Local Area Network (WLAN) Capability Package and requirements of the DoD CIO memo are not implemented, this is a finding.'
  desc 'fix', 'Implement key requirements of the DoD CIO Memorandum, “Use of Commercial Mobile Device (CMD) in the Department of Defense (DoD).'
  impact 0.5
  ref 'DPMS Target CSfC Policy - WLAN CP'
  tag check_id: 'C-44833r2_chk'
  tag severity: 'medium'
  tag gid: 'V-36593'
  tag rid: 'SV-48095r1_rule'
  tag stig_id: 'WIR-CWLAN-04'
  tag gtitle: 'Follow DoD CMD policy for campus WLAN clients'
  tag fix_id: 'F-41232r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Designated Approving Authority', 'Information Assurance Manager']
  tag ia_controls: 'ECWN-1'
end
