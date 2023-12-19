control 'SV-202098' do
  title 'The network device must allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  desc 'In order to ensure network devices have a sufficient storage capacity in which to write the audit logs, they need to be able to allocate audit record storage capacity.  The task of allocating audit record storage capacity is usually performed during initial device setup if it is modifiable. 

The value for the organization-defined audit record storage requirement will depend on the amount of storage available on the network device, the anticipated volume of logs, the frequency of transfer from the network device to centralized log servers, and other factors.'
  desc 'check', 'Determine if the network device allocates audit record storage capacity in accordance with organization-defined audit record storage requirements.

This requirement may be verified by configuration review or vendor-provided information. This requirement may be met through use of a properly configured syslog server if the device is configured to use the syslog server.

If audit record store capacity is not allocated in accordance with organization-defined audit record storage requirements, this is a finding.'
  desc 'fix', 'Configure the network device to allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2224r381929_chk'
  tag severity: 'medium'
  tag gid: 'V-202098'
  tag rid: 'SV-202098r879730_rule'
  tag stig_id: 'SRG-APP-000357-NDM-000293'
  tag gtitle: 'SRG-APP-000357'
  tag fix_id: 'F-2225r381930_fix'
  tag 'documentable'
  tag legacy: ['SV-69321', 'V-55075']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
