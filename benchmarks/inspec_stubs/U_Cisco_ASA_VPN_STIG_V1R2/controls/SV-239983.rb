control 'SV-239983' do
  title 'The Cisco ASA VPN remote access server must be configured to generate log records when successful and/or unsuccessful VPN connection attempts occur.'
  desc 'Without generating log records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Log records can be generated from various components within the information system (e.g., module or policy filter).

This requirement only applies to components where this is specific to the function of the device, such as application layer gateway (ALG), which provides these access control and auditing functions on behalf of an application. This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify the ASA generates log records when successful and/or unsuccessful VPN connection attempts occur as shown in the example below.

logging host INDM_INTERFACE 10.1.1.12
logging class svc trap notifications

Note: A logging list can be used as an alternative to using class.

If the ASA does not generate log records when successful and/or unsuccessful VPN connection attempts occur, this is a finding.'
  desc 'fix', 'Configure the ASA to generate log records when successful and/or unsuccessful VPN connection attempts occur as shown in the example below.

ASA2(config)# logging class svc trap notifications'
  impact 0.5
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43216r666353_chk'
  tag severity: 'medium'
  tag gid: 'V-239983'
  tag rid: 'SV-239983r666355_rule'
  tag stig_id: 'CASA-VN-000720'
  tag gtitle: 'SRG-NET-000492-VPN-001980'
  tag fix_id: 'F-43175r666354_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
