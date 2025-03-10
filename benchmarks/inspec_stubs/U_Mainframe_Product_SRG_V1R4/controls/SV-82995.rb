control 'SV-82995' do
  title 'The Mainframe Product must automatically shut down the information system, restart the information system, and/or implement security safeguards as conditions as defined in site security plan when integrity violations are discovered.'
  desc 'Unauthorized changes to software, firmware, and information can occur due to errors or malicious activity (e.g., tampering). Information includes metadata, such as security attributes associated with information. State-of-the-practice integrity-checking mechanisms (e.g., parity checks, cyclical redundancy checks, cryptographic hashes) and associated tools can automatically monitor the integrity of information systems and hosted applications.

Organizations may define different integrity checking and anomaly responses by type of information (e.g., firmware, software, user data); by specific information (e.g., boot firmware, boot firmware for a specific types of machines); or a combination of both. Automatic implementation of specific safeguards within organizational information systems includes, for example, reversing the changes, halting the information system, restarting the information system, notification to the appropriate personnel or roles, or triggering audit alerts when unauthorized modifications to critical security files occur.

This capability must take into account operational requirements for availability for selecting an appropriate response.'
  desc 'check', 'If the Mainframe Product has no function or capability for integrity verification, this is not applicable.

Examine installation and configuration settings. 

If the Mainframe Product is not configured to automatically shut down the information system, restart the information system, and/or implement security safeguards as conditions as defined in site security plan when integrity violations are discovered, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to automatically shut down the information system, restart the information system, and/or implement security safeguards as conditions as defined in site security plan when integrity violations are discovered.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-69037r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68505'
  tag rid: 'SV-82995r1_rule'
  tag stig_id: 'SRG-APP-000480-MFP-000379'
  tag gtitle: 'SRG-APP-000480-MFP-000379'
  tag fix_id: 'F-74621r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002715']
  tag nist: ['SI-7 (5)']
end
