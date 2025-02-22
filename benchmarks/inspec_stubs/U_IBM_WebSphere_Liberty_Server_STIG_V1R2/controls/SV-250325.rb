control 'SV-250325' do
  title 'The WebSphere Liberty Server must log remote session and security activity.'
  desc 'Security auditing must be configured in order to log remote session activity. Security auditing will not be performed unless the audit feature (audit-1.0) has been enabled. The security feature (appSecurity-2.0) must be enabled for the security auditing to capture security transactions. The servlet (servlet-3.1) feature must be enabled to generate web-based security events. The ejb (ejbLite-3.1) feature must be enabled to generate ejb-based security events. Remote session activity will then be logged, regardless of the user attempting that activity.

'
  desc 'check', 'Review the ${server.config.dir}/server.xml file, ensureaudit-1.0 and appSecurity-2.0 are defined within the <featureManager> setting in the server.xml file. 

If audit-1.0 and appSecurity-2.0 are not defined within the <featureManager> setting in the server.xml file, this is a finding. 

EXAMPLE:
<featureManager>
<feature>audit-1.0</feature>
<feature>appSecurity-3.0</feature>
<feature>servlet-3.1</feature>
<feature>ejbLite-3.1</feature>
</featureManager>'
  desc 'fix', 'To log remote access events, the featureManager setting in the ${server.config.dir}/server.xml must contain the audit, appSecurity, and ejbLite features. 

<featureManager>
<feature>audit-1.0</feature>
<feature>appSecurity-2.0</feature>
</featureManager>'
  impact 0.5
  ref 'DPMS Target IBM WebSphere Liberty Server'
  tag check_id: 'C-53760r862969_chk'
  tag severity: 'medium'
  tag gid: 'V-250325'
  tag rid: 'SV-250325r862971_rule'
  tag stig_id: 'IBMW-LS-000040'
  tag gtitle: 'SRG-APP-000016-AS-000013'
  tag fix_id: 'F-53714r862970_fix'
  tag satisfies: ['SRG-APP-000016-AS-000013', 'SRG-APP-000080-AS-000045', 'SRG-APP-000089-AS-000050', 'SRG-APP-000091-AS-000052', 'SRG-APP-000095-AS-000056', 'SRG-APP-000096-AS-000059', 'SRG-APP-000097-AS-000060', 'SRG-APP-000098-AS-000061', 'SRG-APP-000099-AS-000062', 'SRG-APP-000100-AS-000063', 'SRG-APP-000101-AS-000072', 'SRG-APP-000266-AS-000168', 'SRG-APP-000343-AS-000030', 'SRG-APP-000172-AS-000121']
  tag 'documentable'
  tag cci: ['CCI-000067', 'CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000135', 'CCI-000162', 'CCI-000166', 'CCI-000169', 'CCI-000172', 'CCI-001312', 'CCI-001487', 'CCI-002234']
  tag nist: ['AC-17 (1)', 'AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-3 (1)', 'AU-9 a', 'AU-10', 'AU-12 a', 'AU-12 c', 'SI-11 a', 'AU-3 f', 'AC-6 (9)']
end
