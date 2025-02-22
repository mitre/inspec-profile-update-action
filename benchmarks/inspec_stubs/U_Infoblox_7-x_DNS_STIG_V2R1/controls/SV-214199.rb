control 'SV-214199' do
  title 'The DNS server implementation must follow procedures to re-role a secondary name server as the master name server should the master name server permanently lose functionality.'
  desc 'Failing to an unsecure condition negatively impacts application security and can lead to system compromise. Failure conditions include, for example, loss of communications among critical system components or between system components and operational facilities. Fail-safe procedures include, for example, alerting operator personnel and providing specific instructions on subsequent steps to take (e.g., do nothing, reestablish system settings, shut down processes, restart the system, or contact designated organizational personnel).

If a component such as the DNSSEC or TSIG/SIG(0) signing capabilities were to fail, the DNS server should shut itself down to prevent continued execution without the necessary security components in place. Transactions such as zone transfers would not be able to work correctly anyway in this state.'
  desc 'check', 'Within an Infoblox Grid, configuration control is done through the Grid Master. In the event of a Grid Member failure, upon replacement, the Grid Master will configure the new system to replace the failed member.

A Grid Master Candidate can be configured to alleviate issues in the event of a Grid Master failure. The Grid Master will replicate the entire database to the Grid Master Candidate, which can be promoted to the Grid Master role if needed. 

Review Grid, Grid Manger configuration to ensure a Grid Master Candidate is configured.

If the site does not have a Grid Master Candidate, or local backup and policy guidance on system recovery, this is a finding.'
  desc 'fix', 'Refer to the Infoblox NIOS Administration Guide, Chapters "Deploying a Grid", and "Configuring DNS Zones", section "Assigning Zone Authority to Name Servers" if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15414r295860_chk'
  tag severity: 'medium'
  tag gid: 'V-214199'
  tag rid: 'SV-214199r612370_rule'
  tag stig_id: 'IDNS-7X-000640'
  tag gtitle: 'SRG-APP-000451-DNS-000069'
  tag fix_id: 'F-15412r295861_fix'
  tag 'documentable'
  tag legacy: ['SV-83083', 'V-68593']
  tag cci: ['CCI-002775', 'CCI-000366']
  tag nist: ['SI-17', 'CM-6 b']
end
