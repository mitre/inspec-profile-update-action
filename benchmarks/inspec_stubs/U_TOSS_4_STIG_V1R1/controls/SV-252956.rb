control 'SV-252956' do
  title 'TOSS must protect wireless access to the system using authentication of users and/or devices.'
  desc 'Allowing devices and users to connect to the system without first authenticating them allows untrusted access and can lead to a compromise or attack.

Wireless technologies include, for example, microwave, packet radio (UHF/VHF), 802.11x, and Bluetooth. Wireless networks use authentication protocols (e.g., EAP/TLS, PEAP), which provide credential protection and mutual authentication.

This requirement applies to those operating systems that control wireless devices.

'
  desc 'check', 'Verify there are no wireless interfaces configured on the system with the following command:

Note: This requirement is Not Applicable for systems that do not have physical wireless network radios.

$ sudo nmcli device status
DEVICE TYPE STATE CONNECTION
virbr0 bridge connected virbr0
wlp7s0 wifi connected wifiSSID
enp6s0 ethernet disconnected --
p2p-dev-wlp7s0 wifi-p2p disconnected --
lo loopback unmanaged --
virbr0-nic tun unmanaged --

If a wireless interface is configured and has not been documented and approved by the Information System Security Officer (ISSO), this is a finding.'
  desc 'fix', 'Configure the system to disable all wireless network interfaces with the following command:

$ sudo nmcli radio all off'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56409r824190_chk'
  tag severity: 'medium'
  tag gid: 'V-252956'
  tag rid: 'SV-252956r824192_rule'
  tag stig_id: 'TOSS-04-020160'
  tag gtitle: 'SRG-OS-000299-GPOS-00117'
  tag fix_id: 'F-56359r824191_fix'
  tag satisfies: ['SRG-OS-000299-GPOS-00117', 'SRG-OS-000300-GPOS-00118', 'SRG-OS-000481-GPOS-00481']
  tag 'documentable'
  tag cci: ['CCI-001443', 'CCI-001444', 'CCI-002418']
  tag nist: ['AC-18 (1)', 'AC-18 (1)', 'SC-8']
end
