control 'SV-222585' do
  title 'The application must fail to a secure state if system initialization fails, shutdown fails, or aborts fail.'
  desc 'Failure to a known safe state helps prevent systems from failing to a state that may cause loss of data or unauthorized access to system resources. Applications or systems that fail suddenly and with no incorporated failure state planning may leave the hosting system available but with a reduced security protection capability. Preserving information system state information also facilitates system restart and return to the operational mode of the organization with less disruption of mission-essential processes.

In general, application security mechanisms should be designed so that a failure will follow the same execution path as disallowing the operation. For example, security methods, such as isAuthorized(), isAuthenticated(), and validate(), should all return false if there is an exception during processing. If security controls can throw exceptions, they must be very clear about exactly what that condition means.

Abort refers to stopping a program or function before it has finished naturally. The term abort refers to both requested and unexpected terminations.'
  desc 'check', 'Review application design documentation, vulnerability scanner reports and interview application administrator to identify application components.

The design of the application should account for the following:

- Connections to databases are left open
- Access control mechanisms are disabled
- Data left in temporary locations

Testing application failure will require taking down parts of the application.

Review the vulnerability assessment configuration settings included in vulnerability report.

Examine the application test plans and procedures to determine if this type of failure was previously tested.

If test plans exist, validate the tests by performing a subset of the checks.

If test plans do not exist, an application failure must be simulated.

Simulate a failure. This can be accomplished by stopping the web server service and/or the database service. Also, for applications using web services stop the web service and/or the database.

Check to ensure that application data is still protected. Some examples of tests follow:

- Try to submit SQL queries to the database. Verify that the database requires authentication before returning data.
- Try to read the application source files; access should not be granted to these files because the application is not operating.
- Try to open database files; data should not be available because the application is not operational.

If the application fails in such a way that the application security controls are rendered inoperable, this is a finding.'
  desc 'fix', 'Fix any vulnerability found when the application is an insecure state (initialization, shutdown and aborts).'
  impact 0.7
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24255r493663_chk'
  tag severity: 'high'
  tag gid: 'V-222585'
  tag rid: 'SV-222585r508029_rule'
  tag stig_id: 'APSC-DV-002310'
  tag gtitle: 'SRG-APP-000225'
  tag fix_id: 'F-24244r493664_fix'
  tag 'documentable'
  tag legacy: ['SV-84843', 'V-70221']
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
