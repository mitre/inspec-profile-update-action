control 'SV-80731' do
  title 'The HP FlexFabric Switch must allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  desc 'In order to ensure network devices have a sufficient storage capacity in which to write the audit logs, they need to be able to allocate audit record storage capacity. The task of allocating audit record storage capacity is usually performed during initial device setup if it is modifiable. 

The value for the organization-defined audit record storage requirement will depend on the amount of storage available on the HP FlexFabric Switch, the anticipated volume of logs, the frequency of transfer from the HP FlexFabric Switch to centralized log servers, and other factors.'
  desc 'check', 'Enter the command display logfile summary to verify audit record storage has been allocated in accordance with the organization-defined audit record storage requirements.

If the switch has not been configured to allocate audit record storage in accordance with the organization-defined audit record storage requirements, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.

[HP] info-center security-logfile size-quota 10

Note: The security logfile size in set in MB'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66887r2_chk'
  tag severity: 'medium'
  tag gid: 'V-66241'
  tag rid: 'SV-80731r2_rule'
  tag stig_id: 'HFFS-ND-000095'
  tag gtitle: 'SRG-APP-000357-NDM-000293'
  tag fix_id: 'F-72317r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
