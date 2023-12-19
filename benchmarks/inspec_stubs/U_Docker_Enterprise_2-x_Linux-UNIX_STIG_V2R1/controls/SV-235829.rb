control 'SV-235829' do
  title 'The Docker Enterprise per user limit login session control must be set per the requirements in the System Security Plan (SSP).'
  desc %q(The Universal Control Plane (UCP) component of Docker Enterprise includes a built-in access authorization mechanism called eNZi which can be integrated with an LDAP server and allows for automatic user session termination after organization-defined conditions or trigger events requiring session disconnect. The lifetime minutes login session control is configured with a default of 60 minutes (1 hour) and the renewal threshold minutes is configured with a default of 20 minutes. For reference, the lifetime login session control in UCP specifies the initial lifetime (in minutes) of a session from the moment it is generated. The renewal threshold setting indicates a period of time (in minutes) before the expiration of a session where, if used, a session will be extended by the current configured lifetime from then. This value cannot be greater than the configured lifetime. A value equal to the lifetime means that sessions will be extended with every use. A value of zero indicates that sessions should never be extended but this may result in unexpectedly being logged out if the session expires while performing a series of actions in the UI. This configuration only applies to both the UCP and Docker Trusted Registry (DTR) management consoles and not when connecting via the command line. When connecting via the command line, this control is not applicable.

It's important to note that the notion of a session varies depending on how one is connecting to a UCP cluster or DTR. In all of these cases, there is no specific session termination capability. Either the session times out, the user's client bundle has expired, or a user explicitly logs out. This has been outlined as follows:

(UCP and DTR UIs) When connecting to a UCP cluster or DTR via the web console, a user's session is active until any of the following conditions is met:
- the session expires based on the values configured for "Lifetime Minutes" and "Renewal Threshold Minutes" in the UCP Admin Settings
- the user explicitly clicks the "Sign Out" button

(UCP and DTR CLIs) When connecting to a UCP cluster or DTR via the command line using a client bundle, a user's session is active until any of the following conditions is met:
- the certificate contained within a user's client bundle hasn't expired
- the public key in the certificate contained with a user's client bundle is no long associated with that user (i.e. a client bundle is revoked from within the UCP user management options)
- the user's account is no longer active (either explicitly disabled from within the UCP user management options or at the LDAP server)
- the user's password is changed

*NOTE: Docker Engine - Enterprise, by itself, does not meet the requirements of this control. If the intent is to use Docker in a model consistent with the access control policies as required by this control, obtain and properly configure the UCP component of Docker Enterprise.)
  desc 'check', %q(Check that the "Per User Limit" Login Session Control in the UCP Admin Settings are set according to the System Security Plan but not set to "0". 

via UI:

In the UCP web console, navigate to "Admin Settings" | "Authentication & Authorization" and verify the "Per User Limit" field is set according to the settings described in the SSP. If the per user limit setting is not set to the value defined in the SSP or is set to "0", this is a finding.

via CLI:

Linux (requires curl and jq): As a Docker EE Admin, execute the following commands from a machine with connectivity to the UCP management console. Replace [ucp_url] with the UCP URL, [ucp_username] with the username of a UCP administrator and [ucp_password] with the password of a UCP administrator.

AUTHTOKEN=$(curl -sk -d '{"username":"[ucp_username]","password":"[ucp_password]"}' https://[ucp_url]/auth/login | jq -r .auth_token)
curl -sk -H "Authorization: Bearer $AUTHTOKEN" https://[ucp_url]/api/ucp/config-toml

Look for the "per_user_limit" entry under the "[auth.sessions]" section in the output, and verify that it is set according to the requirements of this control.

If the "per_user_limit" entry under the "[auth.sessions]" section in the output is not set according to the value defined in the SSP, or if the per user limit is set to "0", then this is a finding.)
  desc 'fix', %q(Set the "Per User Limit" Login Session Control in the UCP Admin Settings per the requirements set forth by the SSP but not "0".

via UI:

In the UCP web console, navigate to "Admin Settings" | "Authentication & Authorization" and set the "Per User Limit" field according to the SSP.

via CLI:

Linux (requires curl and jq): As a Docker EE Admin, execute the following commands from a machine with connectivity to the UCP management console. Replace [ucp_url] with the UCP URL, [ucp_username] with the username of a UCP administrator and [ucp_password] with the password of a UCP administrator.

AUTHTOKEN=$(curl -sk -d '{"username":"[ucp_username]","password":"[ucp_password]"}' https://[ucp_url]/auth/login | jq -r .auth_token)
curl -sk -H "Authorization: Bearer $AUTHTOKEN" https://[ucp_url]/api/ucp/config-toml > ucp-config.toml

Open the "ucp-config.toml" file, set the "per_user_limit" entry under the "[auth.sessions]" section according to the SSP but not 0. Save the file.

Execute the following commands to update UCP with the new configuration:

curl -sk -H "Authorization: Bearer $AUTHTOKEN" --upload-file ucp-config.toml https://[ucp_url]/api/ucp/config-toml)
  impact 0.3
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39048r627612_chk'
  tag severity: 'low'
  tag gid: 'V-235829'
  tag rid: 'SV-235829r627614_rule'
  tag stig_id: 'DKER-EE-002970'
  tag gtitle: 'SRG-APP-000295'
  tag fix_id: 'F-39011r627613_fix'
  tag 'documentable'
  tag legacy: ['SV-104829', 'V-95691']
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
