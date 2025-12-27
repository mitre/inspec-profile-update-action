control 'SV-250343' do
  title 'The WebSphere Liberty Server must allocate JVM log record storage capacity in accordance with organization-defined log record storage requirements.'
  desc 'JVM logs are logs used to store application and runtime related events, rather than audit related events. They are mainly used to diagnose application or runtime bugs. However, they are useful for providing more context when correlated with audit related events. 

By default, Liberty automatically logs the console.log, messages.log, and trace.log but these default settings must be validated.'
  desc 'check', 'Review the ${server.config.dir}/bootstrap.properties file, verify console logging is not turned off. If the property com.ibm.ws.logging.console.log.level=OFF, this is a finding. 

Review the ${server.config.dir}/server.xml file and verify the logging traceSpecification setting is configured according to system capacity requirements. If the logging traceSpecification settings are not configured, this is a finding.

EXAMPLE:
<logging traceSpecification="*=info=enabled:my.package.*=all" maxFileSize="40" maxFiles="20"/>'
  desc 'fix', 'Edit the bootstrap.properties file and configure the  com.ibm.ws.logging.console.log.level=ON. 

Edit the ${server.config.dir}/server.xml file. Configure <logging traceSpecification> in accordance with local policy and system storage limits.

EXAMPLE:
<logging traceSpecification="*=info=enabled:my.package.*=all" maxFileSize="40" maxFiles="20"/>, 

where maxFileSize is set to the maximum file size defined in local policy and maxFiles is set to the maximum number of historical files defined in local policy and in accordance with system storage limits.'
  impact 0.5
  ref 'DPMS Target IBM WebSphere Liberty Server'
  tag check_id: 'C-53778r795080_chk'
  tag severity: 'medium'
  tag gid: 'V-250343'
  tag rid: 'SV-250343r850901_rule'
  tag stig_id: 'IBMW-LS-000830'
  tag gtitle: 'SRG-APP-000357-AS-000038'
  tag fix_id: 'F-53732r850900_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
