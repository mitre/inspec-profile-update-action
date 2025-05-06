control 'SV-239922' do
  title 'The Cisco ASA must be configured to allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  desc 'In order to ensure network devices have a sufficient storage capacity in which to write the audit logs, they need to be able to allocate audit record storage capacity.  The task of allocating audit record storage capacity is usually performed during initial device setup if it is modifiable. 

The value for the organization-defined audit record storage requirement will depend on the amount of storage available on the network device, the anticipated volume of logs, the frequency of transfer from the network device to centralized log servers, and other factors.'
  desc 'check', 'Verify the Cisco ASA is configured with a logfile size. The configuration should look like the example below.

logging flash-bufferwrap
logging flash-minimum-free nnnnnnn
logging flash-maximum-allocation nnnnnnn

If the Cisco ASA is not configured to allocate audit record storage capacity in accordance with organization-defined audit record storage requirements, this is a finding.'
  desc 'fix', 'Configure the buffer size for logging as shown in the example below.

ASA(config)# logging flash-maximum-allocation nnnnnnn
ASA(config)# logging flash-minimum-free nnnnnnn'
  impact 0.5
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43155r666127_chk'
  tag severity: 'medium'
  tag gid: 'V-239922'
  tag rid: 'SV-239922r851026_rule'
  tag stig_id: 'CASA-ND-000920'
  tag gtitle: 'SRG-APP-000357-NDM-000293'
  tag fix_id: 'F-43114r666128_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
