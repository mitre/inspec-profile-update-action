control 'SV-4634' do
  title 'Bluetooth (and Zigbee) devices must not be used to send, receive, store, or process classified information.'
  desc 'Classified data could be compromised since Bluetooth (and Zigbee) devices do not meet DoD encryption requirements for classified data.'
  desc 'check', 'NOTE: The check also applies to Wireless USB (WUSB) devices. This check does not apply to wireless email devices (Blackberry, Windows Mobile, etc.). See the appropriate wireless email device checklist for Bluetooth requirements for these devices.

Verify compliance by reviewing the user agreement or security briefing to see if personnel have been properly instructed in the policy that devices with Bluetooth radios cannot be used for or around classified. Mark as a finding if the user agreement or security briefing does not exist or does not adequately cover the requirement.'
  desc 'fix', 'Ensure the users are trained on need to comply with this requirement and/or site procedures document the policy.'
  impact 0.7
  ref 'DPMS Target Wireless Client'
  tag check_id: 'C-11516r1_chk'
  tag severity: 'high'
  tag gid: 'V-4634'
  tag rid: 'SV-4634r1_rule'
  tag stig_id: 'WIR0410'
  tag gtitle: 'Bluetooth devices are not used for classified'
  tag fix_id: 'F-34124r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECWN-1'
end
