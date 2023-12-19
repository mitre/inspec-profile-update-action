control 'SV-14613' do
  title 'A device’s wired network interfaces (e.g., Ethernet) must be disconnected or otherwise disabled when wireless connections are in use.'
  desc 'If a client device supports simultaneous use of wireless and wired connections, then this increases the probability that an adversary who can access the device using its wireless interface can then route traffic through the device’s wired interface to attack devices on the wired network or obtain sensitive DoD information.'
  desc 'check', 'Review client devices and verify that there is some technical procedure to disable the wireless network interface when the wired network interface is active (e.g., connected to a network via an Ethernet cable). 

Examples of compliant implementations: 
- Client side connection management software products have configuration settings that disable wireless connections when a wired connection is active. 
- Microsoft Windows hardware profiles can be created that disable assigned wireless network interfaces when the Ethernet connection is active.

To check compliance, select a sample of devices (3-4), and establish a network connection using the wireless interface.  Test that the wireless interface is active using a command line utility such as ifconfig (UNIX/Linux), or ipconfig (Windows), or management tools such as Network Connections within the Windows Control Panel. Then plug the device into an active Ethernet port (or other wired network).  Repeat the process used to check that the connection was active to verify it is now disabled. 

Mark as a finding if one or more of the tested devices do not disable the wireless interface upon connection to a wired network.  Also mark as finding if the device does not have the capability to disable the wireless interface when the wired interface is active.'
  desc 'fix', 'Ensure the wired network interfaces on a WLAN client are disconnected or otherwise disabled when wireless network connections are in use.'
  impact 0.5
  ref 'DPMS Target L3 KOV-26 Talon'
  tag check_id: 'C-11465r3_chk'
  tag severity: 'medium'
  tag gid: 'V-14002'
  tag rid: 'SV-14613r2_rule'
  tag stig_id: 'WIR0170'
  tag gtitle: 'Simultaneous use of wired and wireless interfaces'
  tag fix_id: 'F-13489r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECWN-1'
end
