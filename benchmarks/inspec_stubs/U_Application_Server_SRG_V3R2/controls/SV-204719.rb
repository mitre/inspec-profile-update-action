control 'SV-204719' do
  title 'The application server must generate log records when successful/unsuccessful attempts to access subject privileges occur.'
  desc "Accessing a subject's privileges can be used to elevate a lower-privileged subject's privileges temporarily in order to cause harm to the application server or to gain privileges to operate temporarily for a designed purpose.  When these actions take place, the event needs to be logged.

Application servers either provide a local user store, or they integrate with enterprise user stores like LDAP.  When the application server provides the user store and enforces authentication, the application server must generate a log record when modification of privileges is successfully or unsuccessfully performed."
  desc 'check', 'Review the application server documentation and the system configuration to determine if the application server generates log records when successful/unsuccessful attempts are made to access privileges.

If log records are not generated, this is a finding.'
  desc 'fix', 'Configure the application server to generate log records when privileges are successfully/unsuccessfully accessed.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4839r282804_chk'
  tag severity: 'medium'
  tag gid: 'V-204719'
  tag rid: 'SV-204719r508029_rule'
  tag stig_id: 'SRG-APP-000091-AS-000052'
  tag gtitle: 'SRG-APP-000091'
  tag fix_id: 'F-4839r282805_fix'
  tag 'documentable'
  tag legacy: ['V-35143', 'SV-46430']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
