control 'SV-246933' do
  title 'ONTAP must allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  desc 'In order to ensure network devices have a sufficient storage capacity in which to write the audit logs, they need to be able to allocate audit record storage capacity. The task of allocating audit record storage capacity is usually performed during initial device setup if it is modifiable.

The value for the organization-defined audit record storage requirement will depend on the amount of storage available on the network device, the anticipated volume of logs, the frequency of transfer from the network device to centralized log servers, and other factors.'
  desc 'check', 'To ensure audit record storage capacity is sufficient, use remote syslogging. Use "cluster log-forwarding show" to see the that a remote syslog server is configured for ONTAP.

If ONTAP cannot allocate audit record storage capacity in accordance with organization-defined audit record storage requirements, this is a finding.'
  desc 'fix', 'Configure a remote syslog server for ONTAP with "cluster log-forwarding create -destination <IP address>".'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50365r769129_chk'
  tag severity: 'medium'
  tag gid: 'V-246933'
  tag rid: 'SV-246933r769131_rule'
  tag stig_id: 'NAOT-AU-000001'
  tag gtitle: 'SRG-APP-000357-NDM-000293'
  tag fix_id: 'F-50319r769130_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
