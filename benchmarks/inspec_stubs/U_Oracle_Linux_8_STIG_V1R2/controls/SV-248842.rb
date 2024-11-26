control 'SV-248842' do
  title 'OL 8 wireless network adapters must be disabled.'
  desc 'Without protection of communications with wireless peripherals, confidentiality and integrity may be compromised because unprotected communications can be intercepted and read, altered, or used to compromise the OL 8 operating system. 
 
This requirement applies to wireless peripheral technologies (e.g., wireless mice, keyboards, displays, etc.) used with OL 8 systems. Wireless peripherals (e.g., Wi-Fi/Bluetooth/IR keyboards, mice, and pointing devices and Near Field Communications [NFC]) present a unique challenge by creating an open, unsecured port on a computer. Wireless peripherals must meet DoD requirements for wireless data transmission and be approved for use by the Authorizing Official (AO). Although some wireless peripherals, such as mice and pointing devices, do not ordinarily carry information that need to be protected, modification of communications with these wireless peripherals may be used to compromise the OL 8 operating system. Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. 
 
Protecting the confidentiality and integrity of communications with wireless peripherals can be accomplished by physical means (e.g., employing physical barriers to wireless radio frequencies) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, logical means (cryptography) do not have to be employed, and vice versa. If the wireless peripheral is only passing telemetry data, encryption of the data may not be required.

'
  desc 'check', 'Verify there are no wireless interfaces configured on the system with the following command. 
 
Note: This requirement is not applicable for systems that do not have physical wireless network radios. 
 
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
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52276r780090_chk'
  tag severity: 'medium'
  tag gid: 'V-248842'
  tag rid: 'SV-248842r780092_rule'
  tag stig_id: 'OL08-00-040110'
  tag gtitle: 'SRG-OS-000299-GPOS-00117'
  tag fix_id: 'F-52230r780091_fix'
  tag satisfies: ['SRG-OS-000299-GPOS-00117', 'SRG-OS-000300-GPOS-00118', 'SRG-OS-000481-GPOS-000481']
  tag 'documentable'
  tag cci: ['CCI-001443', 'CCI-001444', 'CCI-002418']
  tag nist: ['AC-18 (1)', 'AC-18 (1)', 'SC-8']
end
