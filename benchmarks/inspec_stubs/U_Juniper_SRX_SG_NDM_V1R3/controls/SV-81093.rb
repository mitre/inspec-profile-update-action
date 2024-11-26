control 'SV-81093' do
  title 'The Juniper SRX Services Gateway must implement service redundancy to protect against or limit the effects of common types of Denial of Service (DoS) attacks on the device itself.'
  desc 'Service redundancy, may reduce the susceptibility to some DoS attacks.

Organizations must consider the need for service redundancy in accordance with DoD policy. If service redundancy is required then this technical control is applicable.

The Juniper SRX can configure your system to monitor the health of the interfaces belonging to a redundancy group.'
  desc 'check', "If service redundancy is not required by the organization's policy, this is not a finding.

Verify the configuration is working properly: 

[edit]
show chassis cluster interfaces command.

If service redundancy is not configured, this is a finding."
  desc 'fix', 'Interfaces can be monitored by a redundancy group for automatic failover to another node. Assign a weight to the interface to be monitored.

This configuration is an extremely complex configuration. Consult the vendor documentation.

Set the chassis cluster node ID and cluster ID. 
Configure the chassis cluster management interface.
Configure the chassis cluster fabric.
Configure the chassis cluster redundancy group 
Specify the interface to be monitored by a redundancy group. 

Specify the interface to be monitored by a redundancy group. Example:
[edit]
set chassis cluster redundancy-group 1 interface-monitor ge-6/0/2 weight 255'
  impact 0.3
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-67229r1_chk'
  tag severity: 'low'
  tag gid: 'V-66603'
  tag rid: 'SV-81093r1_rule'
  tag stig_id: 'JUSX-DM-000164'
  tag gtitle: 'SRG-APP-000435-NDM-000315'
  tag fix_id: 'F-72679r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
