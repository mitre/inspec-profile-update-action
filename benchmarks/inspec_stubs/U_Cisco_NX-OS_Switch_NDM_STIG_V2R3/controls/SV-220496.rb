control 'SV-220496' do
  title 'The Cisco switch must be configured to allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  desc 'In order to ensure network devices have a sufficient storage capacity in which to write the audit logs, they need to be able to allocate audit record storage capacity. The task of allocating audit record storage capacity is usually performed during initial device setup if it is modifiable. 

The value for the organization-defined audit record storage requirement will depend on the amount of storage available on the network device, the anticipated volume of logs, the frequency of transfer from the network device to centralized log servers, and other factors.'
  desc 'check', 'Verify that the Cisco switch is configured with a logfile size. The configuration should look like the example below:

logging logfile LOGFILE1 6 size nnnnn

If the Cisco switch is not configured to allocate audit record storage capacity in accordance with organization-defined audit record storage requirements, this is a finding.'
  desc 'fix', 'Configure the buffer size for logging as shown in the example below:

SW2(config)# logging logfile LOGFILE1 6 size nnnnn'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch NDM'
  tag check_id: 'C-22211r539209_chk'
  tag severity: 'medium'
  tag gid: 'V-220496'
  tag rid: 'SV-220496r604141_rule'
  tag stig_id: 'CISC-ND-000980'
  tag gtitle: 'SRG-APP-000357-NDM-000293'
  tag fix_id: 'F-22200r539210_fix'
  tag 'documentable'
  tag legacy: ['SV-110641', 'V-101537']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
