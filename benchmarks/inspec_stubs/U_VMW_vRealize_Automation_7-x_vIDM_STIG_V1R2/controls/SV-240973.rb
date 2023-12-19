control 'SV-240973' do
  title 'vIDM must be configured to log activity to the horizon.log file.'
  desc 'The structure and content of error messages need to be carefully considered by the organization and development team. Any application providing too much information in error logs and in administrative messages to the screen risks compromising the data and security of the application and system. The extent to which the application server is able to identify and handle error conditions is guided by organizational policy and operational requirements. Adequate logging levels and system performance capabilities need to be balanced with data protection requirements. The structure and content of error messages needs to be carefully considered by the organization and development team. Application servers must have the capability to log at various levels, which can provide log entries for potential security-related error events. An example is the capability for the application server to assign a criticality level to a failed logon attempt error message, a security-related error message being of a higher criticality.'
  desc 'check', 'At the command prompt, execute the following command:

grep log4j.appender.rollingFile.file /usr/local/horizon/conf/saas-log4j.properties

If the "log4j.appender.rollingFile.file" is not set to "/opt/vmware/horizon/workspace/logs/horizon.log" or is commented out or is missing, this is a finding.'
  desc 'fix', 'Navigate to and open /usr/local/horizon/conf/saas-log4j.properties.

Configure the vIDM policy log file with the following lines:

log4j.appender.rollingFile=org.apache.log4j.RollingFileAppender
log4j.appender.rollingFile.MaxFileSize=50MB
log4j.appender.rollingFile.MaxBackupIndex=7
log4j.appender.rollingFile.Encoding=UTF-8
log4j.appender.rollingFile.file=/opt/vmware/horizon/workspace/logs/horizon.log
log4j.appender.rollingFile.append=true
log4j.appender.rollingFile.layout=org.apache.log4j.PatternLayout
log4j.appender.rollingFile.layout.ConversionPattern=%d{ISO8601} %-5p (%t) [%X{orgId};%X{userId};%X{ip}] %c - %m%n'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x vIDM'
  tag check_id: 'C-44206r676178_chk'
  tag severity: 'medium'
  tag gid: 'V-240973'
  tag rid: 'SV-240973r879655_rule'
  tag stig_id: 'VRAU-VI-000340'
  tag gtitle: 'SRG-APP-000266-AS-000168'
  tag fix_id: 'F-44165r676179_fix'
  tag 'documentable'
  tag legacy: ['SV-100941', 'V-90291']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
