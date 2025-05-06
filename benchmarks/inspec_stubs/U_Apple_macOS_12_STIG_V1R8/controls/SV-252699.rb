control 'SV-252699' do
  title 'The macOS system must be configured with Bluetooth turned off unless approved by the organization.'
  desc 'Without protection of communications with wireless peripherals, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read, altered, or used to compromise the operating system.

This requirement applies to wireless peripheral technologies (e.g., wireless mice, keyboards, displays, etc.) used with an operating system. Wireless peripherals (e.g., Wi-Fi/Bluetooth/IR keyboards, mice, and pointing devices and Near Field Communications [NFC]) present a unique challenge by creating an open, unsecured port on a computer. Wireless peripherals must meet DoD requirements for wireless data transmission and be approved for use by the AO. Even though some wireless peripherals, such as mice and pointing devices, do not ordinarily carry information that need to be protected, modification of communications with these wireless peripherals may be used to compromise the operating system. Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification.

Protecting the confidentiality and integrity of communications with wireless peripherals can be accomplished by physical means (e.g., employing physical barriers to wireless radio frequencies) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa. If the wireless peripheral is only passing telemetry data, encryption of the data may not be required.

'
  desc 'check', %q(If Bluetooth connectivity is required to facilitate use of approved external devices, this is not applicable.

To check if Bluetooth is disabled, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep DisableBluetooth

If the return is null or is not "DisableBluetooth = 1", this is a finding.

To check if the system is configured to disable access to the Bluetooth preference pane and prevent it from being displayed, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 6 -E 'DisabledPreferencePanes|HiddenPreferencePanes'

If the return is not two arrays (HiddenPreferencePanes and DisabledPreferencePanes) each containing: “com.apple.preferences.Bluetooth”, this is a finding.)
  desc 'fix', 'This setting is enforced using the "Custom Policy" and "Restrictions Policy" configuration profiles.'
  impact 0.3
  ref 'DPMS Target Apple macOS 12'
  tag check_id: 'C-56155r819040_chk'
  tag severity: 'low'
  tag gid: 'V-252699'
  tag rid: 'SV-252699r916433_rule'
  tag stig_id: 'APPL-12-002062'
  tag gtitle: 'SRG-OS-000481-GPOS-00481'
  tag fix_id: 'F-56105r819041_fix'
  tag satisfies: ['SRG-OS-000481-GPOS-000481', 'SRG-OS-000319-GPOS-00164']
  tag 'documentable'
  tag cci: ['CCI-001967', 'CCI-002418']
  tag nist: ['IA-3 (1)', 'SC-8']
end
