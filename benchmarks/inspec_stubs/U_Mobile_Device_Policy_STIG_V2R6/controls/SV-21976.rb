control 'SV-21976' do
  title 'Computers with an embedded wireless system must have the radio removed or otherwise physically disable the radio hardware before the computer is used to transfer, receive, store, or process classified information, unless the wireless system has been certified via the DoD Commercial Solutions for Classified (CSfC) program.'
  desc 'With the increasing popularity of wireless networking, most laptops have wireless NICs (network interface cards) installed on the laptop motherboard. Although the system administrator may disable these embedded NICs, the user may purposefully or accidentally enable the device. These devices may also inadvertently transmit ambient sound or electronic signals. Therefore, simply disabling the transmit capability is an inadequate solution for computers processing classified information. In addition, embedded wireless cards do not meet DoD security requirements for classified wireless usage.'
  desc 'check', 'Interview the IAO and inspect a sample of laptops/PCs (check about 10% if possible, with priority to laptops) used at the site for classified data processing.

1. Ask if there are laptops/PCs used to process classified information that have embedded
wireless NICs. No embedded wireless NICs are allowed, including WLAN, Bluetooth, WMAN, cellular, etc. unless the wireless radios have been physically disabled or the wireless system has been certified via the DoD CSfC program.

2. The NIC should be physically removed or physically disabled. Using methods such as tape or software disabling is not acceptable.

Interview the ISSO and determine if the site either bought laptops without wireless NICs (Wi-Fi, Bluetooth, WiMax, etc.) or physically removed or disabled the NICs from laptops. Verify the site has procedures in place to ensure laptops with wireless NICs are not used for classified data processing unless the NICs have been physically disabled or the wireless system is CSfC certified.

If laptops or other computers are used to process classified information and have a wireless NIC installed and the NIC is not physically disabled or the system is not CSfC certified, this is a finding. 

If this is a finding, recommend to the AO that this is a critical finding requiring immediate action'
  desc 'fix', 'Ensure computers with embedded wireless NICs that cannot be removed and are not used to transfer, receive, store, or process classified information unless the NICs have been physically disabled or the wireless system is CSfC certified.'
  impact 0.7
  ref 'DPMS Target Mobile Device Policy'
  tag check_id: 'C-24829r8_chk'
  tag severity: 'high'
  tag gid: 'V-19813'
  tag rid: 'SV-21976r7_rule'
  tag stig_id: 'WIR0045'
  tag gtitle: 'No embedded wireless NIC on classified computers'
  tag fix_id: 'F-20496r5_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
end
