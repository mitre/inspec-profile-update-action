control 'SV-88713' do
  title 'The Cisco IOS XE router must allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  desc 'In order to ensure network devices have a sufficient storage capacity in which to write the audit logs, they need to be able to allocate audit record storage capacity.  The task of allocating audit record storage capacity is usually performed during initial device setup if it is modifiable. 

The value for the organization-defined audit record storage requirement will depend on the amount of storage available on the network device, the anticipated volume of logs, the frequency of transfer from the network device to centralized log servers, and other factors.'
  desc 'check', 'Verify that the Cisco IOS XE router is configured with a logging buffer size.

The configuration should look like the example below:

logging buffered 4096

If a logging buffer size is not configured, this is a finding.'
  desc 'fix', 'Add the following command to configure a buffer size (The range is 4096 to 2147483647 in bytes).

logging buffered 4096'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74129r3_chk'
  tag severity: 'medium'
  tag gid: 'V-74039'
  tag rid: 'SV-88713r2_rule'
  tag stig_id: 'CISR-ND-000097'
  tag gtitle: 'SRG-APP-000357-NDM-000293'
  tag fix_id: 'F-80581r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
