control 'SV-233326' do
  title 'Forescout must authenticate all endpoint devices before establishing a connection and proceeding with posture assessment. This is required for compliance with C2C Step 4.'
  desc 'Authenticating all devices as they connect to the network is the baseline of a good security solution. This is especially important prior to posture assessment to ensure authorized devices are online and have the proper posture prior to accessing the production network.

Device authentication is a solution enabling an organization to manage devices. It is an additional layer of authentication ensuring that only specific preauthorized devices can access the system. Authentication methods for NAC include, but are not limited to, Kerberos, MAC, or other protocols.

The IP Assignment Forescout configuration ensures any IP addresses that should be managed by the configured network will go through the policies within Forescout. Forescout policy structure is applied in a "waterfall" like way that assures all IP addresses start with the top most policy and flow down the policy tree. This policy flow ensures that all endpoints are properly identified, classified, and authenticated prior to the posture assessment.'
  desc 'check', 'If DoD is not at C2C Step 4 or higher, this is not a finding.

Use the Forescout Administrator UI to verify all IP addresses identified in the SSP are configured within the Appliance IP Assignments list.

1. Log on to the Forescout UI.
2. Select Tools >> Option >> Appliance >> IP Assignment.
3. Verify all IP addresses associated with the SSP are labeled within the IP Assignments list.

If Forescout does not authenticate all endpoints prior to establishing a connection and proceeding with posture assessment, this is a finding.'
  desc 'fix', 'Use the Forescout Administrator UI to configure the Appliance IP Assignments list with all IP addresses identified within the SSP. 

1. Log on to the Forescout UI.
2. Select Tools >> Option >> Appliance >> IP Assignment.
3. Configure IP addresses associated with the SSP and label within the IP Assignments list, and then select "Apply".'
  impact 0.5
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36521r811400_chk'
  tag severity: 'medium'
  tag gid: 'V-233326'
  tag rid: 'SV-233326r811401_rule'
  tag stig_id: 'FORE-NC-000180'
  tag gtitle: 'SRG-NET-000343-NAC-001460'
  tag fix_id: 'F-36486r803469_fix'
  tag 'documentable'
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
