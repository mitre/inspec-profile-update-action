control 'SV-222610' do
  title 'The application must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify application components. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements.

Error messages should not include variable names, variable types, SQL strings, or source code. Errors that contain field names from the screen and a description of what should be in the field should not be considered a finding."
  desc 'check', 'Review the application documentation and interview the application administrator for details regarding how the application displays error messages.

Utilize the application as a non-privileged user and attempt to execute functionality that will generate error messages.

Review the error messages displayed to ensure no sensitive information is provided to end users.

If error messages are designed to provide users with just enough detail to pass along to support staff in order to aid in troubleshooting such as date, time, or other generic information, this is not a finding.

If variable names, SQL strings, system path information, or source or program code are displayed in error messages sent to non-privileged users, this is a finding.'
  desc 'fix', 'Configure the server to not send error messages containing system information or sensitive data to users.

Use generic error messages.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24280r493738_chk'
  tag severity: 'medium'
  tag gid: 'V-222610'
  tag rid: 'SV-222610r879655_rule'
  tag stig_id: 'APSC-DV-002570'
  tag gtitle: 'SRG-APP-000266'
  tag fix_id: 'F-24269r493739_fix'
  tag 'documentable'
  tag legacy: ['SV-84895', 'V-70273']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
