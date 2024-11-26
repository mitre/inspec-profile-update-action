control 'SV-250322' do
  title 'Maximum in-memory session count must be set according to application requirements.'
  desc '<0> [object Object]'
  desc 'check', 'Review the System Security plan to determine the maximum number of concurrent sessions allowed. This is a per user setting and must be defined by the application admins.

As a privileged user with access to the server.xml file, review file content and identify the "maxInMemorySessionCount" and the allowOverflow settings.

EXAMPLE:
grep -i maxInMemorySessionCount server.xml

<httpSession maxInMemorySessionCount="xxxx" allowOverflow="false" /> 

If maxInMemorySessionCount is not set in server.xml according to the settings defined in the system security plan or if allowOverflow="true", this is a finding.'
  desc 'fix', 'To limit the max number of concurrent sessions available, the ${server.config.dir}/server.xml must be configured with maxInMemorySessionCount set according to system security plan and allowOverflow="false".

EXAMPLE:
<httpSession maxInMemorySessionCount="5" allowOverflow="false" />'
  impact 0.5
  ref 'DPMS Target IBM WebSphere Liberty Server'
  tag check_id: 'C-53757r795017_chk'
  tag severity: 'medium'
  tag gid: 'V-250322'
  tag rid: 'SV-250322r862962_rule'
  tag stig_id: 'IBMW-LS-000010'
  tag gtitle: 'SRG-APP-000001-AS-000001'
  tag fix_id: 'F-53711r795018_fix'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
