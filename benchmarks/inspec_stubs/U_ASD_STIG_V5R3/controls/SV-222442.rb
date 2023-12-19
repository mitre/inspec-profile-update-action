control 'SV-222442' do
  title 'The application must provide audit record generation capability for the destruction of session IDs.'
  desc 'Applications should destroy session IDs at the end of a user session in order to terminate user access to the application session and to reduce the possibility of an unauthorized attacker high jacking the session and impersonating the user. It is important to log when session IDs are destroyed for forensic purposes.

Web based applications will often utilize an application server that creates, manages and logs session IDs.  It is acceptable for the application to delegate this requirement to the application server.'
  desc 'check', 'Access the management interface for the application or configuration file and evaluate the log/audit management settings.

Determine if the setting that enables session ID destruction event auditing is activated.

Terminate a user session within the application and review the logs to ensure the session destruction event was recorded.

If the application is not configured to log session ID destruction events, or if the application has no means to enable auditing of session ID destruction events, this is a finding.

If a web-based application delegates session ID destruction to an application server, this is not a finding. 

If the application generates audit logs by default when session IDs are destroyed, and that behavior cannot be disabled, this is not a finding.'
  desc 'fix', 'Enable session ID destruction event auditing.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24112r493234_chk'
  tag severity: 'medium'
  tag gid: 'V-222442'
  tag rid: 'SV-222442r879559_rule'
  tag stig_id: 'APSC-DV-000630'
  tag gtitle: 'SRG-APP-000089'
  tag fix_id: 'F-24101r493235_fix'
  tag 'documentable'
  tag legacy: ['V-69365', 'SV-83987']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
