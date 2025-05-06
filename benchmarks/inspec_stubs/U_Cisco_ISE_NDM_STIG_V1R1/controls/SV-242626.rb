control 'SV-242626' do
  title 'The Cisco ISE must limit audit record storage capacity for all locally stored logs.'
  desc 'In order to ensure network devices have a sufficient storage capacity in which to write the audit logs, they need to be able to allocate audit record storage capacity. The task of allocating audit record storage capacity is usually performed during initial device setup if it is modifiable. 

The value for the organization-defined audit record storage requirement will depend on the amount of storage available on the network device, the anticipated volume of logs, the frequency of transfer from the network device to centralized log servers, and other factors.'
  desc 'check', 'Examine the local log purge setting.

show logging internal
or 
Choose Administration >> System >> Logging >> Local Log Settings >> Local Log Storage Period.

If local logs are set to purge after a locally established period, this is not a finding.'
  desc 'fix', 'Configure syslog purge settings. Use the following process to delete local logs after a certain period of time. This is set based on the local environment and size of the implementation. 

1. Choose Administration >> System >> Logging >> Local Log Settings.
2. In the Local Log Storage Period field, enter the maximum number of days to keep the log entries in the configuration source.
3. Click "Delete Logs Now" to delete the existing log files at any time before the expiration of the storage period.
4. Click "Save".

Note: The system is designed to delete logs if the size of the localStore folder reaches 97 GB, regardless of the configured Local Log Storage Period.'
  impact 0.5
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45901r714186_chk'
  tag severity: 'medium'
  tag gid: 'V-242626'
  tag rid: 'SV-242626r714188_rule'
  tag stig_id: 'CSCO-NM-000200'
  tag gtitle: 'SRG-APP-000357-NDM-000293'
  tag fix_id: 'F-45858r714187_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
