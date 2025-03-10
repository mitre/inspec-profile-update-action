control 'SV-235836' do
  title 'The Docker Enterprise log aggregation/SIEM systems must be configured to send an alert the ISSO/ISSM when unauthorized software is installed.'
  desc 'A Docker image is analogous to software in the context of this control.

All components of Docker Enterprise can be configured to send logs to a remote syslog server in order to meet the requirements of this control. Universal Control Plane (UCP) remote syslog configuration is done via the UCP configuration settings. Docker Trusted Registry (DTR) remote syslog configuration is done via an appropriate Docker Engine - Enterprise logging driver.

The UCP and DTR components of Docker Enterprise provide audit record generation capabilities. Audit logs capture all HTTP actions for the following endpoints: Kubernetes API, Swarm API and UCP API. The following UCP API endpoints are excluded from audit logging (where "*" designates a wildcard of exclusions): "/_ping", "/ca", "/auth", "/trustedregistryca", "/kubeauth", "/metrics", "/info", "/version*", "/debug", "/openid_keys", "/apidocs", "kubernetesdocs" and "/manage". Audit log verbosity can be set to one of the following levels: "none", "metadata", or "request". To meet the requirements of this control, the "request" verbosity level must be configured in UCP.

The data captured at each level for UCP and the eNZI authentication and authorization backplane is described below:

"none": audit logging is disabled

"metadata":
 - method and API endpoint for the request
 - UCP user which made the request
 - response status (success/failure)
 - timestamp of the call
 - object ID of created/updated resource (for create/update calls)
 - license key
 - remote address

"request": includes all fields from the "metadata" level, as well as the request payload

DTR audits all events associated with repository activities. Events are considered as follows: create, get, delete, update, send, fail, and scan. The following types are associated with the defined audit events: repository, tag, blob, manifest, webhook, uri, promotion, push mirroring, poll mirroring, garbage collector, system.'
  desc 'check', 'Work with the SIEM administrator to determine if an alert is configured to notify the ISSO/ISSM when unauthorized software is installed on Docker nodes.

If there is no alert configured, this is a finding.'
  desc 'fix', 'Work with the SIEM administrator to create an alert to notify the ISSO/ISSM when unauthorized software is installed on Docker nodes.'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39055r627633_chk'
  tag severity: 'medium'
  tag gid: 'V-235836'
  tag rid: 'SV-235836r627635_rule'
  tag stig_id: 'DKER-EE-003460'
  tag gtitle: 'SRG-APP-000377'
  tag fix_id: 'F-39018r627634_fix'
  tag 'documentable'
  tag legacy: ['SV-104843', 'V-95705']
  tag cci: ['CCI-001811']
  tag nist: ['CM-11 (1)']
end
