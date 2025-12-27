control 'SV-258605' do
  title 'The ICS must be configured to allocate local audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  desc 'In order to ensure network devices have a sufficient storage capacity in which to write the audit logs, they need to be able to allocate audit record storage capacity. The task of allocating audit record storage capacity is usually performed during initial device setup if it is modifiable.

The value for the organization-defined audit record storage requirement will depend on the amount of storage available on the network device, the anticipated volume of logs, the frequency of transfer from the network device to centralized log servers, and other factors.'
  desc 'check', %q(In the ICS Web UI, navigate to System >> Log Monitoring >> User Access >> Settings.

Under the "Minimum Log Size", verify the Max Log Size is equal to or greater than the site's required limit as documented in the SSP (the default is 200 MB).

If the ICS is not configured with a Max Log Size that is equal to or greater than the site's required limit, this is a finding.)
  desc 'fix', 'In the ICS Web UI, navigate to System >> Log Monitoring >> User Access >> Settings.

Go to "Minimum Log Size", set the Max Log Size to the value required by the site. By default, it is set to 200MB.'
  impact 0.5
  ref 'DPMS Target Ivanti Connect Secure NDM'
  tag check_id: 'C-62345r930501_chk'
  tag severity: 'medium'
  tag gid: 'V-258605'
  tag rid: 'SV-258605r930503_rule'
  tag stig_id: 'IVCS-NM-000150'
  tag gtitle: 'SRG-APP-000357-NDM-000293'
  tag fix_id: 'F-62254r930502_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
