control 'SV-83821' do
  title 'The NSX Manager must employ automated mechanisms to assist in the tracking of security incidents.'
  desc "Despite the investment in perimeter defense technologies, enclaves are still faced with detecting, analyzing, and remediating network breaches and exploits that have made it past the network device. An automated incident response infrastructure allows network operations to immediately react to incidents by identifying, analyzing, and mitigating any network device compromise. Incident response teams can perform root cause analysis, determine how the exploit proliferated, and identify all affected nodes, as well as contain and eliminate the threat.
 
The network device assists in the tracking of security incidents by logging detected security events. The audit log and network device application logs capture different types of events. The audit log tracks audit events occurring on the components of the network device. The application log tracks the results of the network device content filtering function. These logs must be aggregated into a centralized server and can be used as part of the organization's security incident tracking and analysis."
  desc 'check', "Verify NSX Manager logs are sent to a centralized server and can be used as part of the organization's security incident tracking and analysis.
 
Log on to NSX Manager with credentials authorized for administration, navigate and select Manage Appliance Settings >> Syslog Server >> Edit.

Enter name or IP of the Syslog Server, Port, and Protocol.

If logs are not sent to a centralized server, this is a finding.

Note: TCP is the preferred protocol configuration to protect against network outages and queues logs locally until network connection is restored to a centralized server."
  desc 'fix', %q(Change the logs in NSX Manager to send to a centralized server for use as part of the organization's security incident tracking and analysis.
 
Login to the NSX Manager Web Interface, using credentials authorized for administration.

Navigate from the Home screen >> "Manage Appliance Settings" >> Settings >> General >> Syslog Server

Verify a syslog server has been configured with the correct address, port, and protocol. 

Login to the vCenter with the appropriate credentials for the Network and Security Platform >> Select "Hosts and Clusters" from the inventories panel >> Expand the entire drop-down section on the left panel >> Select a host as indicated by the ESX host icon >> Navigate to the "Manage" section on the newly updated right panel >> Select "Settings" >> "System" >> "Advanced System Settings" >> In the search field within "Advanced System Settings" enter "Syslog.global.logHost" and press enter >> Select the "Syslog.global.logHost" >> Click the pencil icon >> Insert the desired syslog aggregator or SIEM that exists in the customer environment.)
  impact 0.5
  ref 'DPMS Target VMware NSX 6 NDM'
  tag check_id: 'C-69657r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69217'
  tag rid: 'SV-83821r1_rule'
  tag stig_id: 'VNSX-ND-000140'
  tag gtitle: 'SRG-APP-000516-NDM-000342'
  tag fix_id: 'F-75403r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000833']
  tag nist: ['CM-6 b', 'IR-5 (1)']
end
