control 'SV-207529' do
  title 'The VMM must protect the confidentiality and integrity of communications with wireless peripherals.'
  desc 'Without protection of communications with wireless peripherals, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read, altered, or used to compromise the VMM.
This requirement applies to wireless peripheral technologies (e.g., wireless mice, keyboards, displays, etc.) used with a VMM. Wireless peripherals (e.g., Wi-Fi/Bluetooth/IR keyboards, mice, pointing devices, and Near Field Communications [NFC]) present a unique challenge by creating an open, unsecured port on a computer. Wireless peripherals must meet DoD requirements for wireless data transmission and be approved for use by the AO. Even though some wireless peripherals, such as mice and pointing devices, do not ordinarily carry information that needs to be protected, modification of communications with these wireless peripherals may be used to compromise the VMM. Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification.
Protecting the confidentiality and integrity of communications with wireless peripherals can be accomplished by physical means (e.g., employing physical barriers to wireless radio frequencies) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa. If the wireless peripheral is only passing telemetry data, encryption of the data may not be required.'
  desc 'check', 'Verify the VMM protects the confidentiality and integrity of communications with wireless peripherals.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to protect the confidentiality and integrity of communications with wireless peripherals.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7786r365991_chk'
  tag severity: 'medium'
  tag gid: 'V-207529'
  tag rid: 'SV-207529r916433_rule'
  tag stig_id: 'SRG-OS-000481-VMM-002010'
  tag gtitle: 'SRG-OS-000481'
  tag fix_id: 'F-7786r365992_fix'
  tag 'documentable'
  tag legacy: ['SV-79197', 'V-64707']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
