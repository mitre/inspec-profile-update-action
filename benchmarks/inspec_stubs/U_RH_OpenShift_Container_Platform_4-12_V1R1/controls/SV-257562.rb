control 'SV-257562' do
  title 'OpenShift must set server token max age no greater than eight hours.'
  desc 'The setting for OAuth server token max age is used to control the maximum duration for which an issued OAuth access token remains valid. Access tokens serve as a form of authentication and authorization in OAuth-based systems. By setting a maximum age for these tokens, OpenShift helps mitigate security risks associated with long-lived tokens. If a token is compromised, its impact is limited to the maximum age duration, as the token will expire and become invalid after that period. It reduces the window of opportunity for unauthorized access and enhances the security of the system.

By setting a maximum age for access tokens, OpenShift encourages the use of token refresh rather than relying on the same token for an extended period. Regular token refresh helps maintain a higher level of security by ensuring that tokens are periodically revalidated and rotated.'
  desc 'check', %q(To check if the OAuth server token max age is configured, execute the following:

oc get oauth cluster -ojsonpath='{.spec.tokenConfig.accessTokenMaxAgeSeconds}'

If the output timeout value on the OAuth server is >"28800" or missing, this is a finding.

Check the OAuth client token value (this can be set on each client also).

Check all clients OAuth client token max age configuration by execute the following:

oc get oauthclients -ojson | jq -r '.items[] | { accessTokenMaxAgeSeconds: .accessTokenMaxAgeSeconds}'

If the output returns a timeout value of >"28800" for any client, this is a finding.)
  desc 'fix', %q(To set the OAuth server token max age, edit the OAuth server object by executing the following:

oc patch oauth cluster --type merge -p '{"spec":{"tokenConfig":{"accessTokenMaxAgeSeconds": 28800}}}'

To set the OAuth client token max age, edit the OAuth client object by executing the following:

cli in $(oc get oauthclient -oname); do oc patch oauthclient $cli --type=merge -p '{"accessTokenMaxAgeSeconds": 28800}'; done)
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61297r921627_chk'
  tag severity: 'medium'
  tag gid: 'V-257562'
  tag rid: 'SV-257562r921629_rule'
  tag stig_id: 'CNTR-OS-000760'
  tag gtitle: 'SRG-APP-000400-CTR-000960'
  tag fix_id: 'F-61221r921628_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
