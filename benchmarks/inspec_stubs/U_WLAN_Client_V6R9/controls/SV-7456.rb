control 'SV-7456' do
  title 'WLAN clients must not be configured to connect to other WLAN devices without the user initiating a request to establish such a connection.'
  desc 'Many WLAN clients have the capability to automatically connect to particular WLANs when they are available.  This behavior means the user may not know to which WLAN they are connected or even be aware that a WLAN connection is active.  This increases the probability that these open connections may be used for nefarious purposes, especially if an adversary is able to set up WLAN infrastructure to masquerade as the user’s preferred WLAN.  Once the WLAN client is breached, the adversary may be able to obtain DoD sensitive information or use the client device to attack other systems.'
  desc 'check', 'NOTE: This requirement does not apply to tactical wireless systems where the client is configured to connect only specified tactical access point(s).
Detailed Requirement:

- The wireless client must not automatically connect to any wireless network, whether preferred or non-preferred. 

Check Procedures:
Review the configuration settings of the WLAN client on a sample of wireless clients (3-4) and verify it is not configured so that the wireless client automatically connects to any preferred or non-preferred network.  In some wireless client management software, there is a list of preferred or known networks.  There may also be a configuration option such as “Connect when this network is in range”.  These options should be disabled or not selected.  
Mark as a finding if the wireless client is configured to automatically connect to a wireless network.'
  desc 'fix', 'Disable all auto-connect preferences in wireless client devices.'
  impact 0.3
  ref 'DPMS Target Wireless Client'
  tag check_id: 'C-16041r1_chk'
  tag severity: 'low'
  tag gid: 'V-7072'
  tag rid: 'SV-7456r1_rule'
  tag stig_id: 'WIR0185'
  tag gtitle: 'Automatic connections to wireless networks'
  tag fix_id: 'F-15751r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECSC-1'
end
