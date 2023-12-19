control 'SV-235825' do
  title 'The Lifetime Minutes and Renewal Threshold Minutes Login Session Controls must be set to 10 and 0 respectively in Docker Enterprise.'
  desc %q(The Universal Control Plane (UCP) component of Docker Enterprise includes a built-in access authorization mechanism called eNZi which can be integrated with an LDAP server and subsequently terminate all network connections associated with a communications session at the end of the session, or as follows: for in-band management sessions (privileged sessions), the session must be terminated after 10 minutes of inactivity; and for user sessions (non-privileged session), the session must be terminated after 15 minutes of inactivity, except to fulfill documented and validated mission requirements. The lifetime minutes login session control is configured with a default of 60 minutes (1 hour) and the renewal threshold minutes is configured with a default of 20 minutes. For reference, the lifetime login session control in UCP specifies the initial lifetime (in minutes) of a session from the moment it is generated. The renewal threshold setting indicates a period of time (in minutes) before the expiration of a session where, if used, a session will be extended by the current configured lifetime from then. This value cannot be greater than the configured lifetime. A value equal to the lifetime means that sessions will be extended with every use. A value of zero indicates that sessions should never be extended but this may result in unexpectedly being logged out if the session expires while performing a series of actions in the UI. This configuration only applies to both the UCP and Docker Trusted Registry (DTR) management consoles and not when connecting via the command line. When connecting via the command line, this control is not applicable.

It's important to note that the notion of a session varies depending on how one is connecting to a UCP cluster or DTR. In all of these cases, there is no specific session termination capability. Either the session times out, the user's client bundle has expired, or a user explicitly logs out. This has been outlined as follows:

(UCP and DTR UIs) When connecting to a UCP cluster or DTR via the web console, a user's session is active until any of the following conditions is met:
- the session expires based on the values configured for "Lifetime Minutes" and "Renewal Threshold Minutes" in the UCP Admin Settings
- the user explicitly clicks the "Sign Out" button

(UCP and DTR CLIs) When connecting to a UCP cluster or DTR via the command line using a client bundle, a user's session is active until any of the following conditions is met:
- the certificate contained within a user's client bundle hasn't expired
- the public key in the certificate contained with a user's client bundle is no long associated with that user (i.e. a client bundle is revoked from within the UCP user management options)
- the user's account is no longer active (either explicitly disabled from within the UCP user management options or at the LDAP server)
- the user's password is changed

)
  desc 'check', %q(Verify that the "Lifetime Minutes" and "Renewal Threshold Minutes" Login Session Controls in the Universal Control Plane (UCP) Admin Settings to "10" and "0" respectively.

via UI:

In the UCP web console, navigate to "Admin Settings" | "Authentication & Authorization" and verify the "Lifetime Minutes" field is set to "10" and "Renewal Threshold Minutes" field is set to "0". If they are not, then this is a finding.

via CLI:

Linux (requires curl and jq): As a Docker EE Admin, execute the following commands from a machine with connectivity to the UCP management console. Replace [ucp_url] with the UCP URL, [ucp_username] with the username of a UCP administrator and [ucp_password] with the password of a UCP administrator.

AUTHTOKEN=$(curl -sk -d '{"username":"[ucp_username]","password":"[ucp_password]"}' https://[ucp_url]/auth/login | jq -r .auth_token)
curl -sk -H "Authorization: Bearer $AUTHTOKEN" https://[ucp_url]/api/ucp/config-toml

Look for the "lifetime_minutes" and "renewal_threshold_minutes" entries under the "[auth.sessions]" section in the output, and verify that the "lifetime_minutes" field is set to "10" and the "renewal_threshold_minutes" field is set to "0". 

If they are not, then this is a finding.)
  desc 'fix', %q(Set the "Lifetime Minutes" and "Renewal Threshold Minutes" Login Session Controls in the UCP Admin Settings to "10" and "0" respectively.

via UI:

In the UCP web console, navigate to "Admin Settings" | "Authentication & Authorization" and set the "Lifetime Minutes" and "Renewal Threshold Minutes" fields to "10" and "0" respectively.

via CLI:

Linux (requires curl and jq): As a Docker EE Admin, execute the following commands from a machine with connectivity to the UCP management console. Replace [ucp_url] with the UCP URL, [ucp_username] with the username of a UCP administrator and [ucp_password] with the password of a UCP administrator.

AUTHTOKEN=$(curl -sk -d '{"username":"[ucp_username]","password":"[ucp_password]"}' https://[ucp_url]/auth/login | jq -r .auth_token)
curl -sk -H "Authorization: Bearer $AUTHTOKEN" https://[ucp_url]/api/ucp/config-toml > ucp-config.toml

Open the "ucp-config.toml" file, set the "lifetime_minutes" and "renewal_threshold_minutes" entries under the "[auth.sessions]" section to "10" and "0" respectively.

Execute the following commands to update UCP with the new configuration:

curl -sk -H "Authorization: Bearer $AUTHTOKEN" --upload-file ucp-config.toml https://[ucp_url]/api/ucp/config-toml)
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39044r627600_chk'
  tag severity: 'medium'
  tag gid: 'V-235825'
  tag rid: 'SV-235825r627602_rule'
  tag stig_id: 'DKER-EE-002490'
  tag gtitle: 'SRG-APP-000190'
  tag fix_id: 'F-39007r627601_fix'
  tag satisfies: ['SRG-APP-000190', 'SRG-APP-000002', 'SRG-APP-000003', 'SRG-APP-000295', 'SRG-APP-000389', 'SRG-APP-000400']
  tag 'documentable'
  tag legacy: ['SV-104821', 'V-95683']
  tag cci: ['CCI-000057', 'CCI-000060', 'CCI-002007', 'CCI-001133', 'CCI-002038', 'CCI-002361']
  tag nist: ['AC-11 a', 'AC-11 (1)', 'IA-5 (13)', 'SC-10', 'IA-11', 'AC-12']
end
