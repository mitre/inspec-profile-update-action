control 'SV-207248' do
  title 'The VPN Gateway must generate log records when successful and/or unsuccessful VPN connection attempts occur.'
  desc 'Without generating log records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Log records can be generated from various components within the information system (e.g., module or policy filter).

This requirement only applies to components where this is specific to the function of the device, such as application layer gateway (ALG), which provides these access control and auditing functions on behalf of an application. This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify the VPN Gateway generates log records when successful and/or unsuccessful VPN connection attempts occur.

If the VPN Gateway does not generate log records when successful and/or unsuccessful VPN connection attempts occur, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to generate log records when successful and/or unsuccessful VPN connection attempts occur.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7508r378365_chk'
  tag severity: 'medium'
  tag gid: 'V-207248'
  tag rid: 'SV-207248r608988_rule'
  tag stig_id: 'SRG-NET-000492-VPN-001980'
  tag gtitle: 'SRG-NET-000492'
  tag fix_id: 'F-7508r378366_fix'
  tag 'documentable'
  tag legacy: ['V-97191', 'SV-106329']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
