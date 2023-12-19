control 'SV-217298' do
  title 'The SUSE operating system wireless network adapters must be disabled unless approved and documented.'
  desc 'Without protection of communications with wireless peripherals, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read, altered, or used to compromise the SUSE operating system.

This requirement applies to wireless peripheral technologies (e.g., wireless mice, keyboards, displays, etc.) used with A SUSE operating system. Wireless peripherals (e.g., Wi-Fi/Bluetooth/IR Keyboards, Mice, and Pointing Devices and Near Field Communications [NFC]) present a unique challenge by creating an open, unsecured port on a computer. Wireless peripherals must meet DoD requirements for wireless data transmission and be approved for use by the AO. Even though some wireless peripherals, such as mice and pointing devices, do not ordinarily carry information that need to be protected, modification of communications with these wireless peripherals may be used to compromise the SUSE operating system. Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification.

Protecting the confidentiality and integrity of communications with wireless peripherals can be accomplished by physical means (e.g., employing physical barriers to wireless radio frequencies) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa. If the wireless peripheral is only passing telemetry data, encryption of the data may not be required.

'
  desc 'check', 'Verify that the SUSE operating system has no wireless network adapters enabled.

Check that there are no wireless interfaces configured on the system with the following command:

# wicked show all

lo up
link: #1, state up
type: loopback
config: compat:suse:/etc/sysconfig/network/ifcfg-lo
leases: ipv4 static granted
leases: ipv6 static granted
addr: ipv4 127.0.0.1/8 [static]
addr: ipv6 ::1/128 [static]

eth0 up
link: #2, state up, mtu 1500
type: ethernet, hwaddr 06:00:00:00:00:01
config: compat:suse:/etc/sysconfig/network/ifcfg-eth0
leases: ipv4 dhcp granted
leases: ipv6 dhcp granted, ipv6 auto granted
addr: ipv4 10.0.0.100/16 [dhcp]
route: ipv4 default via 10.0.0.1 proto dhcp

wlan0 up
link: #3, state up, mtu 1500
type: wireless, hwaddr 06:00:00:00:00:02
config: wicked:xml:/etc/wicked/ifconfig/wlan0.xml
leases: ipv4 dhcp granted
addr: ipv4 10.0.0.101/16 [dhcp]
route: ipv4 default via 10.0.0.1 proto dhcp

If a wireless interface is configured it must be documented and approved by the local Authorizing Official.

If a wireless interface is configured and has not been documented and approved, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to disable all wireless network interfaces with the following command:

For each interface of type wireless, bring the interface into "down" state:

# wicked ifdown wlan0

For each interface of type wireless with a configuration of type "compat:suse:", remove the associated file:

# rm /etc/sysconfig/network/ifcfg-wlan0

For each interface of type wireless, for each configuration of type "wicked:xml:", remove the associated file or remove the interface configuration from the file.

# rm /etc/wicked/ifconfig/wlan0.xml'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18526r370050_chk'
  tag severity: 'medium'
  tag gid: 'V-217298'
  tag rid: 'SV-217298r603262_rule'
  tag stig_id: 'SLES-12-030450'
  tag gtitle: 'SRG-OS-000299-GPOS-00117'
  tag fix_id: 'F-18524r370051_fix'
  tag satisfies: ['SRG-OS-000299-GPOS-00117', 'SRG-OS-000300-GPOS-00118', 'SRG-OS-000481-GPOS-000481']
  tag 'documentable'
  tag legacy: ['V-77505', 'SV-92201']
  tag cci: ['CCI-001443', 'CCI-001444', 'CCI-002418']
  tag nist: ['AC-18 (1)', 'AC-18 (1)', 'SC-8']
end
