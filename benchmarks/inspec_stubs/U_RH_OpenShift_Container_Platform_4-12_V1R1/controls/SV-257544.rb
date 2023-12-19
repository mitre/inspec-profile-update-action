control 'SV-257544' do
  title 'OpenShift must terminate all network connections associated with a communications session at the end of the session, or as follows: for in-band management sessions (privileged sessions), the session must be terminated after 10 minutes of inactivity.'
  desc %q(In OpenShift, the "session token inactivity timeout" on OAuth clients is set to ensure security and protect against potential unauthorized access to user sessions. OAuth is an open standard for secure authorization and authentication between different services. By setting a session token inactivity timeout, OpenShift reduces the risk of unauthorized access to a user's session if they become inactive or leave their session unattended. It helps protect against potential session hijacking or session replay attacks.

OpenShift is designed to efficiently manage resources across the cluster. Active sessions consume resources such as memory and CPU. By setting timeouts, OpenShift can reclaim these resources if a session remains inactive for a certain duration. This helps optimize resource allocation and ensures that resources are available for other active sessions and workloads.

OpenShift provides the ability for automatic time-out to debug node sessions on client versions starting with 4.8.36. By setting a time-out, OpenShift can manage the allocation of resources efficiently. It prevents the scenario where a debug session remains active indefinitely, potentially consuming excessive resources and impacting the performance of other applications running on the cluster.

Allowing debug sessions to run indefinitely could introduce security risks. If a session is left unattended or unauthorized access is gained to a debug session, it could potentially compromise the application or expose sensitive information. By enforcing time-outs, OpenShift reduces the window of opportunity for unauthorized access and helps maintain the security and stability of the platform.

)
  desc 'check', %q(On each administrators terminal, verify the OC client version includes the required idle timeout by executing the following.

oc version

If the client version < "4.8.36", this is a finding.

Determine if the session token inactivity timeout is set on the oauthclients by executing the following.

oc get oauthclients -ojsonpath='{range .items[*]}{.metadata.name}{"\t"}{.accessTokenInactivityTimeoutSeconds}{"\n"}'

The output will list each oauth client name followed by a number. The number represents the timeout in seconds. If no number is displayed, or the timeout value is >600, this is a finding.)
  desc 'fix', %q(Download the latest version of the OC client, and remove/replace any older versions.

For each oauth client that does not have the idle timeout set, or the timeout is set to the wrong duration, run the following command to set the idle timeout value to 10 minutes.

oc patch oauthclient/<CLIENT_NAME> --type=merge -p '{"accessTokenInactivityTimeoutSeconds":600}'

where CLIENT_NAME is the name of the oauthclient identified in the check.)
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61279r921573_chk'
  tag severity: 'medium'
  tag gid: 'V-257544'
  tag rid: 'SV-257544r921575_rule'
  tag stig_id: 'CNTR-OS-000490'
  tag gtitle: 'SRG-APP-000190-CTR-000500'
  tag fix_id: 'F-61203r921574_fix'
  tag satisfies: ['SRG-APP-000190-CTR-000500', 'SRG-APP-000389-CTR-000925']
  tag 'documentable'
  tag cci: ['CCI-001133', 'CCI-002038']
  tag nist: ['SC-10', 'IA-11']
end
