control 'SV-216985' do
  title 'The BGP router must be configured to enable the Generalized TTL Security Mechanism (GTSM).'
  desc "GTSM is designed to protect a router's IP-based control plane from DoS attacks. Many attacks focused on CPU load and line-card overload can be prevented by implementing GTSM on all Exterior Border Gateway Protocol speaking routers. 

GTSM is based on the fact that the vast majority of control plane peering is established between adjacent routers; that is, the Exterior Border Gateway Protocol peers are either between connecting interfaces or between loopback interfaces. Since TTL spoofing is considered nearly impossible, a mechanism based on an expected TTL value provides a simple and reasonably robust defense from infrastructure attacks based on forged control plane traffic."
  desc 'check', 'Review the router configuration.

If the router is not configured to use GTSM for all Exterior Border Gateway Protocol peering sessions, this is a finding.'
  desc 'fix', 'Configure all Exterior Border Gateway Protocol peering sessions to use GTSM.'
  impact 0.3
  ref 'DPMS Target Router'
  tag check_id: 'C-18215r382661_chk'
  tag severity: 'low'
  tag gid: 'V-216985'
  tag rid: 'SV-216985r604135_rule'
  tag stig_id: 'SRG-NET-000362-RTR-000124'
  tag gtitle: 'SRG-NET-000362'
  tag fix_id: 'F-18213r382662_fix'
  tag 'documentable'
  tag legacy: ['SV-70023', 'V-55769']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
