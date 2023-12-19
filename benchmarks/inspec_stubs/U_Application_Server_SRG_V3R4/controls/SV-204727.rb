control 'SV-204727' do
  title 'The application server must generate log records containing the full-text recording of privileged commands or the individual identities of group account users.'
  desc 'Privileged commands are commands that change the configuration or data of the application server.  Since this type of command changes the application server configuration and could possibly change the security posture of the application server, these commands need to be logged to show the full-text of the command executed.  Without the full-text, reconstruction of harmful events or forensic analysis is not possible.

Organizations can consider limiting the additional log information to only that information explicitly needed for specific log requirements.  At a minimum, the organization must log either full-text recording of privileged commands or the individual identities of group users, or both.  The organization must maintain log trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.'
  desc 'check', 'Review the application server documentation and deployment configuration to determine if the application server is configured to generate full-text recording of privileged commands or the individual identities of group users at a minimum.

Have a user execute a privileged command and review the log data to validate that the full-text or identity of the individual is being logged.

If the application server is not meeting this requirement, this is a finding.'
  desc 'fix', 'Configure the application server to generate the full-text recording of privileged commands or the individual identities of group users, or both.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4847r282828_chk'
  tag severity: 'medium'
  tag gid: 'V-204727'
  tag rid: 'SV-204727r879569_rule'
  tag stig_id: 'SRG-APP-000101-AS-000072'
  tag gtitle: 'SRG-APP-000101'
  tag fix_id: 'F-4847r282829_fix'
  tag 'documentable'
  tag legacy: ['V-57417', 'SV-71689']
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
