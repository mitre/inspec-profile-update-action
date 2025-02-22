control 'SV-251024' do
  title 'The Sentry providing mobile device authentication intermediary services must restrict mobile device authentication traffic to specific authentication server(s).'
  desc "User authentication can be used as part of the policy filtering rule sets. Some URLs or network resources can be restricted to authenticated users only. Users are prompted by the application or browser for credentials. Authentication service may be provided by the ALG as an intermediary for the application; however, the authentication credential must be stored in the site's directory services server.

This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user (e.g., proxy capability). This does not apply to authentication for the purpose of configuring the device itself (i.e., device management)."
  desc 'check', %q(If the Sentry does not provide user authentication intermediary services, this is not applicable. 

Verify the Sentry is configured with a preestablished trust relationship and mechanisms with appropriate authorities that validate each user access authorization and privileges.

If Sentry provides user authentication intermediary services for ActiveSync, verify them as follows:
1. In the MobileIron Core Admin Portal, go to Services >> Sentry.
2. Click the "Edit" icon next to Sentry, which opens the "Edit Standalone Sentry" dialog. 
3. Determine if the fields in the form are configured for ActiveSync.
4. Look under "ActiveSync Server(s)".
5. Verify only the ActiveSync Servers' end users are on this list.

If ActiveSync Servers' end users are not the only entities on this list, this is a finding.

If Sentry provides user authentication intermediary services for AppTunnel, verify only the Servers that users should be authenticating to are specified in the Services list.

1. In the MobileIron Core Admin Portal, go to Services >> Sentry.
2. Select the "Edit" icon for an existing Standalone Sentry entry.
3. Review the Approved AppTunnel Services and verify only the Servers that users should be authenticating to are specified in the services list.

If end users are able to access AppTunnel services they should not be accessing, this is a finding.)
  desc 'fix', 'If user authentication intermediary services are provided, configure the Sentry to use a specific authentication server(s).

For ActiveSync services:
1. In the MobileIron Core Admin Portal, go to Services >> Sentry.
2. Select Add New >> Standalone Sentry or click the "Edit" icon for an existing Standalone Sentry entry.
3. Complete the fields in the form for ActiveSync Configuration.
4. Configure approved ActiveSync servers.
5. Click "Save".

For AppTunnel services: 
1. In the MobileIron Core Admin Portal, go to Services >> Sentry.
2. Select Add New >> Standalone Sentry or click the "Edit" icon for an existing Standalone Sentry entry.
3. Complete the fields in the form for AppTunnel Configuration.
4. Configure approved AppTunnel services.
5. Click "Save".'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x ALG'
  tag check_id: 'C-54459r802292_chk'
  tag severity: 'medium'
  tag gid: 'V-251024'
  tag rid: 'SV-251024r802294_rule'
  tag stig_id: 'MOIS-AL-000390'
  tag gtitle: 'SRG-NET-000138-ALG-000089'
  tag fix_id: 'F-54413r802293_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
