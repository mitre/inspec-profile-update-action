control 'SV-79303' do
  title 'The operating system must protect the confidentiality and integrity of communications with wireless peripherals.'
  desc 'Without protection of communications with wireless peripherals, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read, altered, or used to compromise the operating system.

This requirement applies to wireless peripheral technologies (e.g., wireless mice, keyboards, displays, etc.) used with an operating system. Wireless peripherals (e.g., Wi-Fi/Bluetooth/IR Keyboards, Mice, and Pointing Devices and Near Field Communications [NFC]) present a unique challenge by creating an open, unsecured port on a computer. Wireless peripherals must meet DoD requirements for wireless data transmission and be approved for use by the AO. Even though some wireless peripherals, such as mice and pointing devices, do not ordinarily carry information that need to be protected, modification of communications with these wireless peripherals may be used to compromise the operating system. Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification.

Protecting the confidentiality and integrity of communications with wireless peripherals can be accomplished by physical means (e.g., employing physical barriers to wireless radio frequencies) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa. If the wireless peripheral is only passing telemetry data, encryption of the data may not be required.'
  desc 'check', 'Verify the operating system protects the confidentiality and integrity of communications with wireless peripherals. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to protect the confidentiality and integrity of communications with wireless peripherals.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-65497r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64813'
  tag rid: 'SV-79303r1_rule'
  tag stig_id: 'SRG-OS-000481-GPOS-000481'
  tag gtitle: 'SRG-OS-000481-GPOS-000481'
  tag fix_id: 'F-70755r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
