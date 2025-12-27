control 'SV-216533' do
  title 'The Cisco router must be configured to allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  desc 'In order to ensure network devices have a sufficient storage capacity in which to write the audit logs, they need to be able to allocate audit record storage capacity. The task of allocating audit record storage capacity is usually performed during initial device setup if it is modifiable. 

The value for the organization-defined audit record storage requirement will depend on the amount of storage available on the network device, the anticipated volume of logs, the frequency of transfer from the network device to centralized log servers, and other factors.'
  desc 'check', 'Verify that the Cisco router is configured with a logging buffer size as well as on the hard drive. The configuration should look like the example below:

logging archive
 device harddisk
 severity notifications
 file-size 10
 archive-size 100
…
…
…
logging buffered 8888888

If a logging buffer size and the archive size is not configured, this is a finding.

If the Cisco router is not configured to allocate audit record storage capacity in accordance with organization-defined audit record storage requirements, this is a finding.'
  desc 'fix', 'Configure the logging buffer size as well as the active log file size and the amount of storage to be reserved for archive log files as shown in the example below.

RP/0/0/CPU0:R3(config)#logging buffered 8888888
RP/0/0/CPU0:R3(config)#logging archive
RP/0/0/CPU0:R3(config-logging-arch)#severity notifications
RP/0/0/CPU0:R3(config-logging-arch)#device harddisk
RP/0/0/CPU0:R3(config-logging-arch)#archive-size 100 
RP/0/0/CPU0:R3(config-logging-arch)#file-size 10
RP/0/0/CPU0:R3(config-logging-arch)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router NDM'
  tag check_id: 'C-17768r288285_chk'
  tag severity: 'medium'
  tag gid: 'V-216533'
  tag rid: 'SV-216533r879730_rule'
  tag stig_id: 'CISC-ND-000980'
  tag gtitle: 'SRG-APP-000357-NDM-000293'
  tag fix_id: 'F-17765r288286_fix'
  tag 'documentable'
  tag legacy: ['SV-105581', 'V-96443']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
