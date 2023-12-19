control 'SV-257218' do
  title 'The macOS system must be configured with Bluetooth turned off unless approved by the organization.'
  desc 'Without protection of communications with wireless peripherals, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read, altered, or used to compromise the operating system.

This requirement applies to wireless peripheral technologies (e.g., wireless mice, keyboards, displays, etc.) used with an operating system. Wireless peripherals (e.g., Wi-Fi/Bluetooth/IR keyboards, mice, and pointing devices and Near Field Communications [NFC]) present a unique challenge by creating an open, unsecured port on a computer. Wireless peripherals must meet DOD requirements for wireless data transmission and be approved for use by the AO. Even though some wireless peripherals, such as mice and pointing devices, do not ordinarily carry information that need to be protected, modification of communications with these wireless peripherals may be used to compromise the operating system. Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification.

Protecting the confidentiality and integrity of communications with wireless peripherals can be accomplished by physical means (e.g., employing physical barriers to wireless radio frequencies) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa. If the wireless peripheral is only passing telemetry data, encryption of the data may not be required.

'
  desc 'check', 'Verify the macOS system is configured to disable Bluetooth with the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "DisableBluetooth"

DisableBluetooth = 1;

If the result is not "DisableBluetooth = 1" and the use of Bluetooth has not been documented with the ISSO as an operational requirement, this is a finding.

Verify the macOS system is configured to disable access to the Bluetooth preference pane with the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 6 "DisabledPreferencePanes"

If the result is not an array listing "DisabledPreferencePanes" containing "com.apple.preferences.Bluetooth" and the use of Bluetooth has not been documented with the ISSO as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the macOS system to disable Bluetooth and disable access to the Bluetooth preference pane by installing the "Custom Policy" and "Restrictions Policy" configuration profiles.'
  impact 0.3
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60903r905285_chk'
  tag severity: 'low'
  tag gid: 'V-257218'
  tag rid: 'SV-257218r905287_rule'
  tag stig_id: 'APPL-13-002062'
  tag gtitle: 'SRG-OS-000379-GPOS-00164'
  tag fix_id: 'F-60844r905286_fix'
  tag satisfies: ['SRG-OS-000379-GPOS-00164', 'SRG-OS-000481-GPOS-00481']
  tag 'documentable'
  tag cci: ['CCI-001967', 'CCI-002418']
  tag nist: ['IA-3 (1)', 'SC-8']
end
