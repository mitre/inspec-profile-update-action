control 'SV-206777' do
  title 'The Voice Video Endpoint must block both inbound and outbound communications traffic between Unified Capability (UC) and Videoconferencing (VC) clients independently configured by end users and external service providers for voice and video.'
  desc 'Various communication services such as public VoIP and Instant Messaging services route traffic over their own networks and are stored on their own servers; therefore, that traffic can be accessed at any time by the provider and potentially intercepted. 

Communication clients independently configured by end users and external service providers include, for example, instant messaging clients. Traffic blocking does not apply to communication clients that are configured by organizations to perform authorized functions.'
  desc 'check', 'If UC and VC clients cannot be independently configured by either end users or external service providers, this is Not Applicable. 

Verify the Voice Video Endpoint blocks both inbound and outbound communications traffic between UC and VC clients independently configured by end users and external service providers for voice and video. 

If the Voice Video Endpoint does not block both inbound and outbound communications traffic between UC and VC clients independently configured by end users and external service providers, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint to block both inbound and outbound communications traffic between UC and VC clients independently configured by end users and external service providers.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7033r363854_chk'
  tag severity: 'medium'
  tag gid: 'V-206777'
  tag rid: 'SV-206777r604140_rule'
  tag stig_id: 'SRG-NET-000366-VVEP-00014'
  tag gtitle: 'SRG-NET-000366'
  tag fix_id: 'F-7033r363855_fix'
  tag 'documentable'
  tag legacy: ['SV-81197', 'V-66707']
  tag cci: ['CCI-000366', 'CCI-002409']
  tag nist: ['CM-6 b', 'SC-7 (19)']
end
