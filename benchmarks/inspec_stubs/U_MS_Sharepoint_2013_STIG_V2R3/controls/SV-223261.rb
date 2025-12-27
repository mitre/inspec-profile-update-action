control 'SV-223261' do
  title 'SharePoint must implement security functions as a layered structure minimizing interactions between layers of the design and avoiding any dependence by lower layers on the functionality or correctness of higher layers.'
  desc 'The information system isolates security functions from nonsecurity functions by means of an isolation boundary (implemented via partitions and domains) controlling access to, and protecting the integrity of, the hardware, software, and firmware that perform those security functions. The information system maintains a separate execution domain (e.g., address space) for each executing process.'
  desc 'check', 'Review the SharePoint server configuration to ensure security functions as a layered structure minimizing interactions between layers of the design and avoiding any dependence by lower layers on the functionality or correctness of higher layers are implemented.

Check the network location of the Central Administration server.

If the server resides in the DMZ, this is a finding.

Attempt to access Central Administration without first connecting to a management network VPN.

If Central Administration can be accessed over a production network, this is a finding.

Attempt to connect directly to a SharePoint server (i.e., via remote desktop) without first connecting to a management network VPN.

If a remote desktop session can be established via a production network, this is a finding.'
  desc 'fix', 'Configure the SharePoint server to implement security functions as a layered structure minimizing interactions between layers of the design and avoiding any dependence by lower layers on the functionality or correctness of higher layers.

Configure access to Central Administration to be allowed over a management (OOB) network.

Configure Central Administration on a server that resides within the internal network (not on a server in the DMZ).

Configure management access (i.e., remote desktop access and local server access) so that it occurs only via a management network (OOB) and not over a production network.'
  impact 0.5
  ref 'DPMS Target Microsoft SharePoint 2013'
  tag check_id: 'C-24934r430840_chk'
  tag severity: 'medium'
  tag gid: 'V-223261'
  tag rid: 'SV-223261r612235_rule'
  tag stig_id: 'SP13-00-000130'
  tag gtitle: 'SRG-APP-000238'
  tag fix_id: 'F-24922r430841_fix'
  tag 'documentable'
  tag legacy: ['SV-74413', 'V-59983']
  tag cci: ['CCI-001089']
  tag nist: ['SC-3 (5)']
end
