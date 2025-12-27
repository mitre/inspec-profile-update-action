control 'SV-217413' do
  title 'The BIG-IP appliance must be configured to allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  desc 'In order to ensure network devices have a sufficient storage capacity in which to write the audit logs, they need to be able to allocate audit record storage capacity. The task of allocating audit record storage capacity is usually performed during initial device setup if it is modifiable. 

The value for the organization-defined audit record storage requirement will depend on the amount of storage available on the network device, the anticipated volume of logs, the frequency of transfer from the network device to centralized log servers, and other factors.'
  desc 'check', 'Verify the BIG-IP appliance is configured to off-load audit records to a remote syslog server that allocates audit record storage capacity in accordance with organization-defined audit record storage requirements. 

Navigate to the BIG-IP System manager >> System >> Logs >> Configuration >> Remote Logging.

Verify a syslog destination is configured that allocates audit record storage capacity in accordance with organization-defined audit record storage requirements.

If audit record store capacity is not allocated in accordance with organization-defined audit record storage requirements, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use a properly configured syslog server to allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18638r290793_chk'
  tag severity: 'medium'
  tag gid: 'V-217413'
  tag rid: 'SV-217413r557520_rule'
  tag stig_id: 'F5BI-DM-000191'
  tag gtitle: 'SRG-APP-000357-NDM-000293'
  tag fix_id: 'F-18636r290794_fix'
  tag 'documentable'
  tag legacy: ['SV-74631', 'V-60201']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
