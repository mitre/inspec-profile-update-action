control 'SV-237177' do
  title 'ColdFusion must prohibit or restrict the use of nonsecure ports, protocols, modules, and/or services as defined in the PPSM CAL and vulnerability assessments.'
  desc 'Some networking protocols may not meet organizational security requirements to protect data and components.

ColdFusion may host a number of various features, such as the Administrator Console, data sources and various services.  These features all run on TCPIP ports and protocols. This creates the potential that the vendor or ColdFusion administrator may choose to utilize port numbers or protocols that have been deemed unusable by the organization.  When ports or protocols are used that are not secure or authorized by the organization, the ColdFusion feature must be reconfigured to use an authorized port and protocol.

For a list of approved ports and protocols, reference the DoD ports and protocols web site at https://powhatan.iiie.disa.mil/ports/cal.html.'
  desc 'check', 'Access the Administrator Console from a web browser.  If a port is part of the URL, verify that the port used is an approved port.

Within the Administrator Console, navigate to each page under the "Data & Services" menu viewing the port settings for each connection and service.

If the Administrator Console or any "Data & Services" setting is not using an approved port, this is a finding.'
  desc 'fix', 'Reconfigure the services or data connections that are using an unapproved port to use an approved port.'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40396r641624_chk'
  tag severity: 'medium'
  tag gid: 'V-237177'
  tag rid: 'SV-237177r641626_rule'
  tag stig_id: 'CF11-03-000107'
  tag gtitle: 'SRG-APP-000142-AS-000014'
  tag fix_id: 'F-40359r641625_fix'
  tag 'documentable'
  tag legacy: ['SV-76917', 'V-62427']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
