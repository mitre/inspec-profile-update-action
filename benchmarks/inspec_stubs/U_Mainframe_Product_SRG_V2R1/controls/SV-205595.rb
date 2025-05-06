control 'SV-205595' do
  title 'The Mainframe Product must perform an integrity check of information as defined in site security plan at startup, at transitional states as defined in site security plan or security-relevant events, or annually.'
  desc 'Unauthorized changes to information can occur due to errors or malicious activity (e.g., tampering). Information includes metadata, such as security attributes associated with information. State-of-the-practice integrity-checking mechanisms (e.g., parity checks, cyclical redundancy checks, cryptographic hashes) and associated tools can automatically monitor the integrity of information systems and hosted applications.

Security-relevant events include, for example, the identification of a new threat to which organizational information systems are susceptible and the installation of new hardware, software, or firmware. Transitional states include, for example, system startup, restart, shutdown, and abort.

This requirement applies to integrity verification tools that are used to detect unauthorized changes to organization-defined information.'
  desc 'check', 'If the Mainframe Product has no function or capability for integrity verification, this is not applicable.

Examine installation and configuration settings. 

If the Mainframe Product is not configured to perform an integrity check of information as defined in site security plan at startup, at transitional states as defined in site security plan or security-relevant events, or annually, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to perform integrity check of inform as defined in site security plan at startup, at transitional states as defined in site security plan or security-relevant events, or annually.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5861r300012_chk'
  tag severity: 'medium'
  tag gid: 'V-205595'
  tag rid: 'SV-205595r851360_rule'
  tag stig_id: 'SRG-APP-000477-MFP-000376'
  tag gtitle: 'SRG-APP-000477'
  tag fix_id: 'F-5861r300013_fix'
  tag 'documentable'
  tag legacy: ['SV-82993', 'V-68503']
  tag cci: ['CCI-002712']
  tag nist: ['SI-7 (1)']
end
