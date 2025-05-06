control 'SV-222533' do
  title 'The application must authenticate all network connected endpoint devices before establishing any connection.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

For distributed architectures (e.g., service-oriented architectures), the decisions regarding the validation of authentication claims may be made by services separate from the services acting on those decisions.

In such situations, it is necessary to provide authentication decisions (as opposed to the actual authenticators) to the services that need to act on those decisions.

This requirement applies to applications that connect either locally, remotely, or through a network to an endpoint device (including but not limited to: workstations, printers, servers (outside a datacenter), VoIP Phones, VTC CODECs).

Gateways and SOA applications are examples of where this requirement would apply.

End point devices are not:
Client desktop workstations only offer browser-based web application access where the user authenticates at the app layer.

Device authentication is a solution enabling an organization to manage devices. It is an additional layer of authentication ensuring only specific pre-authorized devices can access the system.'
  desc 'check', 'Review the application documentation, implementation documentation and interview the application administrator.

Identify if the application utilizes Web Services/Service-Oriented Architecture (SOA). Using the web services framework that has been implemented, have the application administrator identify the remote devices allowed to communicate to the service provider.

If the application is designed to provide end-user, interactive application access only and does not use web services or allow connections from remote devices, this requirement is not applicable.

Identify the authentication mechanism used to authenticate the remote consumers/devices. Commonly available authentication methods are Client Certificate Authentication and Basic Authentication.

The Basic Authentication method provides insufficient protection for authentication sessions and is not allowed.

If no authentication mechanism is used to authenticate remote service consumers/devices, or if Basic Authentication is used to authentication remote service consumers/devices, this is a finding.'
  desc 'fix', 'Configure the application to authenticate all network connected endpoint devices/service consumers before establishing connections.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24203r493507_chk'
  tag severity: 'medium'
  tag gid: 'V-222533'
  tag rid: 'SV-222533r849462_rule'
  tag stig_id: 'APSC-DV-001650'
  tag gtitle: 'SRG-APP-000394'
  tag fix_id: 'F-24192r493508_fix'
  tag 'documentable'
  tag legacy: ['SV-84171', 'V-69549']
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
