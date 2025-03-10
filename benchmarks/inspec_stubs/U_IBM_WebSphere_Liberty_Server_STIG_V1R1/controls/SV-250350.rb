control 'SV-250350' do
  title 'The WebSphere Liberty Server must generate log records for authentication and authorization events.'
  desc 'Enabling authentication (SECURITY_AUTHN) and authorization (SECURITY_AUTHZ) event handlers configures the server to record security authorization and authentication events. By logging these events, the logs can be analyzed to identify activity that could be related to security events and to aid post mortem forensic analysis.

'
  desc 'check', 'Review the ${server.config.dir}/server.xml file, verify the audit-1.0 feature is enabled. Also verify the auditFile Handler is configured to log AUTHN and AUTHZ events. 

If the audit1.0 feature is not enabled, this is a finding.

If the SECURITY_AUTHN and SECURITY_AUTHZ event handlers are not configured, this is a finding. 

<featureManager>
<feature>audit-1.0</feature>
</featureManager>

    <auditFileHandler>
        <events name="AllAuthn" eventName="SECURITY_AUTHN" />
<events name="AllAuthz" eventName="SECURITY_AUTHZ" />
    </auditFileHandler>'
  desc 'fix', 'Modify the ${server.config.dir}/server.xml file and configure the audit-1.0 feature.

<featureManager>
<feature>audit-1.0</feature>
</featureManager>

Configure the auditFileHandler setting to record SECURITY_AUTHN and SECURITY_AUTHZ events. 

<auditFileHandler>
      <events name="AllAuthn" eventName="SECURITY_AUTHN"/>
<events name="AllAuthz" eventName="SECURITY_AUTHZ" />
    </auditFileHandler>    

Review audit logs located under the ${server.config.dir}/logs directory and ensure AUTHN and AUTHZ events are logged.'
  impact 0.5
  ref 'DPMS Target IBM WebSphere Liberty Server'
  tag check_id: 'C-53785r795101_chk'
  tag severity: 'medium'
  tag gid: 'V-250350'
  tag rid: 'SV-250350r795103_rule'
  tag stig_id: 'IBMW-LS-001190'
  tag gtitle: 'SRG-APP-000499-AS-000224'
  tag fix_id: 'F-53739r795102_fix'
  tag satisfies: ['SRG-APP-000499-AS-000224', 'SRG-APP-000495-AS-000220', 'SRG-APP-000503-AS-000228', 'SRG-APP-000504-AS-000229', 'SRG-APP-000505-AS-000230', 'SRG-APP-000506-AS-000231', 'SRG-APP-000509-AS-000234', 'SRG-APP-000092-AS-000053']
  tag 'documentable'
  tag cci: ['CCI-000172', 'CCI-001464']
  tag nist: ['AU-12 c', 'AU-14 (1)']
end
