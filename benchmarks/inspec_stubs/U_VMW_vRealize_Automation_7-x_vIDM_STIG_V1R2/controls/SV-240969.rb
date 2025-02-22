control 'SV-240969' do
  title 'vIDM must be configured to log activity to the horizon.log file.'
  desc 'Logging must be utilized in order to track system activity, assist in diagnosing system issues, and provide evidence needed for forensic investigations post security incident. Remote access by administrators requires that the admin activity be logged. Application servers provide a web and command line-based remote management capability for managing the application server. Application servers must ensure that all actions related to administrative functionality such as application server configuration are logged.'
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
  tag check_id: 'C-44202r676166_chk'
  tag severity: 'medium'
  tag gid: 'V-240969'
  tag rid: 'SV-240969r879521_rule'
  tag stig_id: 'VRAU-VI-000020'
  tag gtitle: 'SRG-APP-000016-AS-000013'
  tag fix_id: 'F-44161r676167_fix'
  tag 'documentable'
  tag legacy: ['SV-100933', 'V-90283']
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
