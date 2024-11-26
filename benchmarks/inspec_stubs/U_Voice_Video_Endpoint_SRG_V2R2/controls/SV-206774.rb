control 'SV-206774' do
  title 'When using PKI-based authentication, the Voice Video Endpoint used for videoconferencing must implement a local cache of revocation data to support path discovery and validation in the event the network path becomes unavailable.'
  desc 'Without configuring a local cache of revocation data, there is the potential to allow access to users who are no longer authorized (users with revoked certificates). 

This does not apply to authentication for the purpose of configuring the device itself (i.e., device management).'
  desc 'check', 'Verify the Voice Video Endpoint used for videoconferencing, when using PKI-based authentication, implements a local cache of revocation data to support path discovery and validation in the event the network path becomes unavailable.

If the Voice Video Endpoint used for videoconferencing, when using PKI-based authentication, does not implement a local cache of revocation data to support path discovery and validation in the event the network path becomes unavailable, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint used for videoconferencing, when using PKI-based authentication, to implement a local cache of revocation data to support path discovery and validation in the event the network path becomes unavailable.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7030r363845_chk'
  tag severity: 'medium'
  tag gid: 'V-206774'
  tag rid: 'SV-206774r604140_rule'
  tag stig_id: 'SRG-NET-000345-VVEP-00036'
  tag gtitle: 'SRG-NET-000345'
  tag fix_id: 'F-7030r363846_fix'
  tag 'documentable'
  tag legacy: ['V-66755', 'SV-81245']
  tag cci: ['CCI-001991']
  tag nist: ['IA-5 (2) (d)']
end
