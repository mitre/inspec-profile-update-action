control 'SV-95915' do
  title 'The WebSphere Application Server bus security must be enabled.'
  desc 'A service integration bus is a group of one or more application servers or server clusters in a WebSphere® Application Server cell that cooperate to provide asynchronous messaging services. The application servers or server clusters in a bus are known as bus members.

When a bus is created with bus security enabled, the following conditions apply:
The bus requires client authentication.
The bus enforces authorization policy.
The bus requires use of SSL transport chains.'
  desc 'check', 'Review System Security Plan documentation.

Interview the system administrator.

Identify the service integration buses configured on the WAS.

If there are no service integration buses, this requirement is NA.

From the administration console, navigate to Security >> Bus Security.

For each service integration bus, if security is not enabled, this is a finding.'
  desc 'fix', 'From the administration console, navigate to Security >> Bus Security.

For each service integration bus where security is not enabled, click on "Disabled".

Click the check box to "Enable bus security".

Configure the transport settings and authorization policies according to application security access requirements specified in the security plan.'
  impact 0.7
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80871r1_chk'
  tag severity: 'high'
  tag gid: 'V-81201'
  tag rid: 'SV-95915r1_rule'
  tag stig_id: 'WBSP-AS-000140'
  tag gtitle: 'SRG-APP-000315-AS-000095'
  tag fix_id: 'F-87979r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002315']
  tag nist: ['AC-17 (3)']
end
