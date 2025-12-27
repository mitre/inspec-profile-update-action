control 'SV-253918' do
  title 'The Juniper EX switch must be configured to allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  desc 'To ensure network devices have a sufficient storage capacity in which to write the audit logs, they need to be able to allocate audit record storage capacity. The task of allocating audit record storage capacity is usually performed during initial device setup if it is modifiable. 

The value for the organization-defined audit record storage requirement will depend on the amount of storage available on the network device, the anticipated volume of logs, the frequency of transfer from the network device to centralized log servers, and other factors.'
  desc 'check', 'Determine if the network device allocates audit record storage capacity in accordance with organization-defined audit record storage requirements.

This requirement may be verified by configuration review or vendor-provided information. This requirement may be met through use of a properly configured syslog server if the device is configured to use the syslog server.

Junos does not permit configuring audit logging storage space. However, the majority of disk space is reserved for local audit log storage and file are rotated using a first-in-first-out (FIFO) function.
Verify external syslog servers are configured.
[edit system syslog]
host <address 1> {
    any info;
}
host <address 2> {
    any info;
}

If audit record store capacity is not allocated in accordance with organization-defined audit record storage requirements, or the device is not configured to use external syslog server(s), this is a finding.'
  desc 'fix', 'Configure the network device to allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.

Configure external syslog server(s):
set system syslog host <address 1> any info
set system syslog host <address 2> any info'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57370r843785_chk'
  tag severity: 'medium'
  tag gid: 'V-253918'
  tag rid: 'SV-253918r879730_rule'
  tag stig_id: 'JUEX-NM-000410'
  tag gtitle: 'SRG-APP-000357-NDM-000293'
  tag fix_id: 'F-57321r843786_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
