control 'SV-209604' do
  title 'The macOS system must be configured with Bluetooth turned off unless approved by the organization.'
  desc 'Without protection of communications with wireless peripherals, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read, altered, or used to compromise the operating system.

This requirement applies to wireless peripheral technologies (e.g., wireless mice, keyboards, displays, etc.) used with an operating system. Wireless peripherals (e.g., Wi-Fi/Bluetooth/IR Keyboards, Mice, and Pointing Devices and Near Field Communications [NFC]) present a unique challenge by creating an open, unsecured port on a computer. Wireless peripherals must meet DoD requirements for wireless data transmission and be approved for use by the AO. Even though some wireless peripherals, such as mice and pointing devices, do not ordinarily carry information that need to be protected, modification of communications with these wireless peripherals may be used to compromise the operating system. Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification.

Protecting the confidentiality and integrity of communications with wireless peripherals can be accomplished by physical means (e.g., employing physical barriers to wireless radio frequencies) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa. If the wireless peripheral is only passing telemetry data, encryption of the data may not be required.'
  desc 'check', 'If Bluetooth connectivity is required to facilitate use of approved external devices, this is Not Applicable.

To check if Bluetooth is disabled, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep DisableBluetooth

If the return is null or is not "DisableBluetooth = 1", this is a finding.'
  desc 'fix', 'This setting is enforced using the "Custom Policy" configuration profile.'
  impact 0.3
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9855r282294_chk'
  tag severity: 'low'
  tag gid: 'V-209604'
  tag rid: 'SV-209604r610285_rule'
  tag stig_id: 'AOSX-14-002062'
  tag gtitle: 'SRG-OS-000481-GPOS-000481'
  tag fix_id: 'F-9855r282295_fix'
  tag 'documentable'
  tag legacy: ['V-95947', 'SV-105085']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
