control 'SV-215691' do
  title 'The Cisco router must be configured to allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  desc 'In order to ensure network devices have a sufficient storage capacity in which to write the audit logs, they need to be able to allocate audit record storage capacity. The task of allocating audit record storage capacity is usually performed during initial device setup if it is modifiable. 

The value for the organization-defined audit record storage requirement will depend on the amount of storage available on the network device, the anticipated volume of logs, the frequency of transfer from the network device to centralized log servers, and other factors.'
  desc 'check', 'Verify that the Cisco router is configured with a logging buffer size. The configuration should look like the example below:

logging buffered xxxxxxxx informational

If a logging buffer size is not configured, this is a finding.

If the Cisco router is not configured to allocate audit record storage capacity in accordance with organization-defined audit record storage requirements, this is a finding.'
  desc 'fix', 'Configure the buffer size for logging as shown in the example below.

R2(config)#logging buffered xxxxxxxx informational'
  impact 0.5
  ref 'DPMS Target Cisco IOS Router NDM'
  tag check_id: 'C-16885r286035_chk'
  tag severity: 'medium'
  tag gid: 'V-215691'
  tag rid: 'SV-215691r892496_rule'
  tag stig_id: 'CISC-ND-000980'
  tag gtitle: 'SRG-APP-000357-NDM-000293'
  tag fix_id: 'F-16883r286036_fix'
  tag 'documentable'
  tag legacy: ['SV-105253', 'V-96115']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
