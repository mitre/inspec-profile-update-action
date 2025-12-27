control 'SV-205594' do
  title 'The Mainframe product must perform an integrity check of all software from vendors/sources that provide cryptographic mechanisms to enable the validation of code authenticity and integrity at startup, at transitional states as defined in site security plan or security-relevant events, or annually.'
  desc 'Unauthorized changes to software can occur due to errors or malicious activity (e.g., tampering). Software includes, for example, operating systems (with key internal components such as kernels, drivers), middleware, and applications. State-of-the-practice integrity-checking mechanisms (e.g., parity checks, cyclical redundancy checks, cryptographic hashes) and associated tools can automatically monitor the integrity of information systems and hosted applications.

Security-relevant events include, for example, the identification of a new threat to which organizational information systems are susceptible and the installation of new hardware, software, or firmware. Transitional states include, for example, system startup, restart, shutdown, and abort.

This requirement applies to integrity verification tools that are used to detect unauthorized changes to organization-defined software.'
  desc 'check', 'If the Mainframe Product has no function or capability for integrity verification, this is not applicable.

Examine installation and configuration settings. 

If the Mainframe Product is not configured to perform an integrity check of all software from vendors/sources that provide cryptographic mechanisms to enable the validation of code authenticity and integrity at startup, at transitional states as defined in site security plan or security-relevant events, or annually, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to perform an integrity check of all software from vendors/sources that provide cryptographic mechanisms to enable the validation of code authenticity and integrity at startup, at transitional states as defined in site security plan or security-relevant events, or annually.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5860r300009_chk'
  tag severity: 'medium'
  tag gid: 'V-205594'
  tag rid: 'SV-205594r864583_rule'
  tag stig_id: 'SRG-APP-000475-MFP-000374'
  tag gtitle: 'SRG-APP-000475'
  tag fix_id: 'F-5860r539615_fix'
  tag 'documentable'
  tag legacy: ['SV-82991', 'V-68501']
  tag cci: ['CCI-002710']
  tag nist: ['SI-7 (1)']
end
