control 'SV-233896' do
  title 'The Infoblox DNS server implementation must follow procedures to re-role a secondary name server as the master name server should the master name server permanently lose functionality.'
  desc 'Failing to an unsecure condition negatively impacts application security and can lead to system compromise. Failure conditions include, for example, loss of communications among critical system components or between system components and operational facilities. Fail-safe procedures include, for example, alerting operator personnel and providing specific instructions on subsequent steps to take (e.g., do nothing, reestablish system settings, shut down processes, restart the system, or contact designated organizational personnel).

If a component such as DNSSEC signing capabilities were to fail, the DNS server should shut itself down to prevent continued execution without the necessary security components in place. Transactions such as zone transfers would not be able to work correctly in this state.'
  desc 'check', 'Validation of this configuration item requires review of the network architecture and security configuration in addition to DNS server configuration to validate external name servers are not accessible from the internal network when a split DNS configuration is implemented. 

1. Navigate to Data Management >> DNS >> Members tab. 
2. Review the network configuration and access control of each Infoblox member that has the DNS service running. 
3. Select each grid member and click "Edit".  
4. Review the "Queries" tab to verify that both queries and recursion options are enabled and allowed only from the respective client networks. 

If a split DNS configuration is not used, this is not a finding.

If there is no access control configured or access control does not restrict queries and recursion to the respective client network, this is a finding.'
  desc 'fix', '1. Refer to the Infoblox NIOS Administrator Guide, Chapters "Deploying a Grid", and "Configuring DNS Zones", section "Assigning Zone Authority to Name Servers", if necessary. 
2. Configure a Grid Master Candidate or define a local policy to re-role a secondary name server.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37081r611208_chk'
  tag severity: 'medium'
  tag gid: 'V-233896'
  tag rid: 'SV-233896r621666_rule'
  tag stig_id: 'IDNS-8X-400038'
  tag gtitle: 'SRG-APP-000451-DNS-000069'
  tag fix_id: 'F-37046r611209_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002775']
  tag nist: ['CM-6 b', 'SI-17']
end
