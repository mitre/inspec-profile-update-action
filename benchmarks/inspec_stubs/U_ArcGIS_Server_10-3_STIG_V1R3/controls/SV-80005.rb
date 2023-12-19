control 'SV-80005' do
  title 'The ArcGIS Server Windows authentication must authenticate all endpoint devices before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

For distributed architectures (e.g., service-oriented architectures), the decisions regarding the validation of authentication claims may be made by services separate from the services acting on those decisions. In such situations, it is necessary to provide authentication decisions (as opposed to the actual authenticators) to the services that need to act on those decisions.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network, Internet). A remote connection is any connection with a device communicating through an external network (e.g., the Internet).

Because of the challenges of applying this requirement of a large scale, organizations are encouraged to only apply the requirement to those limited number (and type) of devices that truly need to support this capability.

'
  desc 'check', 'Review the ArcGIS for Server configuration to ensure that the application authenticates all network connected endpoint devices before establishing any connection. Substitute the target environment’s values for [bracketed] variables.

Within IIS >> within the [“arcgis”] application >> Authentication >> Verify that “Windows Authentication” is “Enabled”.
Verify that “Anonymous Authentication” is “Disabled”.
If “Windows Authentication” is not enabled, or “Anonymous Authentication” is enabled, this is a finding.

This control is not applicable for ArcGIS Server deployments configured to allow anonymous access.

This control is not applicable for ArcGIS Server deployments which are integrated with and protected by one or more third party DoD compliant certificate authentication solutions.'
  desc 'fix', 'Configure ArcGIS for Server to accept Personal Identity Verification (PIV) credentials. Substitute the target environment’s values for [bracketed] variables.

Enable Active Directory Client Certificate Authentication "To map client certificates by using Active Directory mapping."'
  impact 0.7
  ref 'DPMS Target ArcGIS 10.3'
  tag check_id: 'C-66097r2_chk'
  tag severity: 'high'
  tag gid: 'V-65515'
  tag rid: 'SV-80005r2_rule'
  tag stig_id: 'AGIS-00-000174'
  tag gtitle: 'SRG-APP-000395'
  tag fix_id: 'F-71457r3_fix'
  tag satisfies: ['SRG-APP-000395', 'SRG-APP-000317', 'SRG-APP-000345', 'SRG-APP-000389', 'SRG-APP-000390', 'SRG-APP-000394']
  tag 'documentable'
  tag cci: ['CCI-001958', 'CCI-001967', 'CCI-002038', 'CCI-002039', 'CCI-002142', 'CCI-002238']
  tag nist: ['IA-3', 'IA-3 (1)', 'IA-11', 'IA-11', 'AC-2 (10)', 'AC-7 b']
end
