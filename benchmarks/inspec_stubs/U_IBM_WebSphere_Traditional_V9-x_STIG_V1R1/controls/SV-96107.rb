control 'SV-96107' do
  title 'The WebSphere Application Server distribution and consistency services (DCS) transport links must be encrypted.'
  desc 'A Core Group (HA Domain) is a component of the high availability manager function. It can contain stand-alone servers, cluster members, node agents, administrative agents, and the deployment manager. 

Core groups rely on DCS, which uses a reliable multicast message (RMM) system for transport. RMM can use one of several wire transport technologies. Depending on your environment, sensitive information might be transmitted over DCS. For example, data in DynaCache and the security subject cache are transmitted using DCS. To ensure this, select a transport type of channel framework and DCS-Secure as channel chain for each core group.

Be aware that DCS always authenticates messages when global security is enabled. Once the transport is encrypted, you then have a highly secure channel.

Once you have done this, all services that rely on DCS are now using an encrypted and authenticated transport. Those services are DynaCache, memory-to-memory session replication, core groups, Web services caching, and stateful session bean persistence.'
  desc 'check', 'From the admin console navigate to Servers >> Core groups.

For every Core Group listed, select the Core Group [CoreGroup Name]. 

Under "Transport Type", select the "Channel Framework" button.

If the "transport chain" drop down box is not set to "DCS-Secure", this is a finding.'
  desc 'fix', 'From the admin console navigate to Core groups >> for every Core Group listed.

Select the [Core Group Name].

Under "Transport" type, select "CHANNEL_FRAMEWORK" button.

In the "Transport chain" drop down box set to "DCS-SECURE".

Click "Save".

Sync the configuration.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-81103r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81393'
  tag rid: 'SV-96107r1_rule'
  tag stig_id: 'WBSP-AS-001620'
  tag gtitle: 'SRG-APP-000440-AS-000166'
  tag fix_id: 'F-88179r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end
