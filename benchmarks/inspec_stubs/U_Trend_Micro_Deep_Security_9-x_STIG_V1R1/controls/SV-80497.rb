control 'SV-80497' do
  title 'Trend Deep Security must implement security safeguards when integrity violations are discovered.'
  desc 'Unauthorized changes to software, firmware, and information can occur due to errors or malicious activity (e.g., tampering). Information includes metadata, such as security attributes associated with information. State-of-the-practice integrity-checking mechanisms (e.g., parity checks, cyclical redundancy checks, cryptographic hashes) and associated tools can automatically monitor the integrity of information systems and hosted applications.

Organizations may define different integrity checking and anomaly responses by type of information (e.g., firmware, software, user data); by specific information (e.g., boot firmware, boot firmware for a specific types of machines); or a combination of both. Automatic implementation of specific safeguards within organizational information systems includes, for example, reversing the changes, halting the information system, restarting the information system, notification to the appropriate personnel or roles, or triggering audit alerts when unauthorized modifications to critical security files occur.

This capability must take into account operational requirements for availability for selecting an appropriate response.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure security safeguards are implemented when integrity violations are discovered.

Verify Integrity Monitoring is enabled for all connected host systems by navigating to Policy >> Policy Editor. 

Navigate to Integrity Monitoring >> General, verify that the Integrity Monitoring module is "On" and configured with assigned rules.

If "Integrity Monitoring" is not set to "On", this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to implement security safeguards when integrity violations are discovered.

To enable Integrity Monitoring functionality on a computer:

In the Policy/Computer editor, go to Integrity Monitoring >> General

Select "On", and then click "Assign/Unassign".

Select the appropriate rules applicable to the information system being monitored.

Click "Save".'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66655r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66007'
  tag rid: 'SV-80497r1_rule'
  tag stig_id: 'TMDS-00-002130'
  tag gtitle: 'SRG-APP-000480'
  tag fix_id: 'F-72083r3_fix'
  tag 'documentable'
  tag cci: ['CCI-002715']
  tag nist: ['SI-7 (5)']
end
