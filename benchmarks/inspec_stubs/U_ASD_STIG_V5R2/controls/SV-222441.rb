control 'SV-222441' do
  title 'The application must provide audit record generation capability for the creation of session IDs.'
  desc 'Applications create session IDs at the onset of a user session in order to manage user access to the application and differentiate between different user sessions. It is important to log the creation of these session ID creation events for forensic purposes.

It is equally important to not log the session ID itself. Logging the session ID puts active sessions at risk if log data is compromised. Specific session ID information should be removed, masked, sanitized, or encrypted.

A hash value of the session ID that can be mapped to the session ID is an acceptable method for assuring active session protection when logging session ID information. Alternatively, logging protections that protect the logs and defend from unauthorized access are means to assure log confidentiality and protect session integrity.

Web based applications will often utilize an application server that creates, manages and logs user session IDs.  It is acceptable for the application to delegate this requirement to the application server.'
  desc 'check', 'Access the management interface for the application or configuration file and evaluate the log/audit management settings.

Determine if the setting that enables session ID creation event auditing is activated.

Create a new user session by logging in to the application.

Review the logs to ensure the session creation event was recorded.

If the application is not configured to log session ID creation events, or if no creation event was recorded, this is a finding.

If a web-based application delegates session ID creation to an application server, this is not a finding. 

If the application generates session ID creation event logs by default, and that behavior cannot be disabled, this is not a finding.'
  desc 'fix', 'Enable session ID creation event auditing.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24111r493231_chk'
  tag severity: 'medium'
  tag gid: 'V-222441'
  tag rid: 'SV-222441r508029_rule'
  tag stig_id: 'APSC-DV-000620'
  tag gtitle: 'SRG-APP-000089'
  tag fix_id: 'F-24100r493232_fix'
  tag 'documentable'
  tag legacy: ['V-69363', 'SV-83985']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
