control 'SV-222532' do
  title 'The application must utilize mutual authentication when endpoint device non-repudiation protections are required by DoD policy or by the data owner.'
  desc "Without identifying devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

With one way SSL authentication which is the typical form of SSL authentication done between a web browser client and a web server, the client requests the server certificate to validate the server's identity and establish a secure connection.

When SSL mutual authentication is used, the server is configured to request the client’s certificate as well so the server can also identify the client.

For distributed architectures (e.g., service-oriented architectures), the decisions regarding the validation of identification claims may be made by services separate from the services acting on those decisions. In such situations, it is necessary to provide the identification decisions (as opposed to the actual identifiers) to the services that need to act on those decisions.

This requirement applies to applications that connect either locally, remotely, or through a network to an endpoint device (including but not limited to: workstations, printers, servers (outside a datacenter), VoIP Phones, VTC CODECs). Gateways and SOA applications are examples of where this requirement would apply."
  desc 'check', 'Review the application documentation and interview the application administrator.

Determine if mutual authentication is mandated by the data owner or by mission data protection objectives and data type.

Review application architecture and design documents.

Identify endpoint devices that interact with the application. These can be SOA gateways, VOIP phones, or other devices that are used to connect to and exchange data with the application.

If the design documentation specifies, this could potentially also include remote client workstations.

In order for two way SSL/mutual authentication to work properly, the server must be configured to request client certificates.

Access the applications management console.

Navigate to the SSL management utility or web page that is used to configure two way mutual authentication.

Verify endpoints are configured for client authentication (mutual authentication).

Some application architectures such as Java configure their settings in text/xml formatted files; in that case, have the application administrator identify the configuration files used by the application.
E.g., web.xml stored in WEB-INF/ sub directory of the application root folder.

Open the web.xml file using a text editor.

Verify the application deployment descriptor for the application and the resource requiring protection under the "login-config" element is set to CLIENT-CERT.

If SSL mutual authentication is required and is not being utilized, this is a finding.'
  desc 'fix', 'Configure the application to utilize mutual authentication when specified by data protection requirements.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24202r493504_chk'
  tag severity: 'medium'
  tag gid: 'V-222532'
  tag rid: 'SV-222532r879599_rule'
  tag stig_id: 'APSC-DV-001640'
  tag gtitle: 'SRG-APP-000158'
  tag fix_id: 'F-24191r493505_fix'
  tag 'documentable'
  tag legacy: ['V-69547', 'SV-84169']
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
