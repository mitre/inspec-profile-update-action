control 'SV-250341' do
  title 'Application security must be enabled on the WebSphere Liberty Server.'
  desc 'Application security enables security for the applications in the environment. This type of security provides application isolation and requirements for authenticating application users. When a user enables security, both administrative and application security is enabled. 

Application security is in effect only when administrative security is enabled via the security feature. If the application server is to be used for only web applications, only the servlet-3.1 feature needs to be defined. If the application server is to be used for only ejb applications, only the ejbLite-3.1 feature needs to be defined. If both web and ejb applications are to be deployed on the application server, then both the servlet-3.1 and ejbLite-3.1 features need to be defined. The check and fix assumes that the application server will have both web and ejb applications deployed.

'
  desc 'check', 'As a user with local file access to ${server.config.dir}/server.xml file, verify application security is enabled. 

If the appSecurity-3.0 feature is not defined within server.xml, this is a finding.

<featureManager>
  <feature>appSecurity-3.0</feature>
</featureManager>'
  desc 'fix', 'Configure the  ${server.config.dir}/server.xml file and add the appSecurity-3.0 feature. 

<featureManager>
<feature>appSecurity-3.0</feature>
</featureManager>

Review ${server.config.dir}/logs/messages.log

Validate log entry that indicates "Security service is ready".'
  impact 0.7
  ref 'DPMS Target IBM WebSphere Liberty Server'
  tag check_id: 'C-53776r795074_chk'
  tag severity: 'high'
  tag gid: 'V-250341'
  tag rid: 'SV-250341r795076_rule'
  tag stig_id: 'IBMW-LS-000770'
  tag gtitle: 'SRG-APP-000315-AS-000094'
  tag fix_id: 'F-53730r795075_fix'
  tag satisfies: ['SRG-APP-000315-AS-000094', 'SRG-APP-000014-AS-000009']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-002314']
  tag nist: ['AC-17 (2)', 'AC-17 (1)']
end
