control 'SV-256039' do
  title 'The Arista BGP router must be configured to enable the Generalized TTL Security Mechanism (GTSM).'
  desc "GTSM is designed to protect a router's IP-based control plane from DoS attacks. Many attacks focused on CPU load and line-card overload can be prevented by implementing GTSM on all Exterior Border Gateway Protocol speaking routers.

GTSM is based on the fact that the vast majority of control plane peering is established between adjacent routers; that is, the Exterior Border Gateway Protocol peers are either between connecting interfaces or between loopback interfaces. Since TTL spoofing is considered nearly impossible, a mechanism based on an expected TTL value provides a simple and reasonably robust defense from infrastructure attacks based on forged control plane traffic."
  desc 'check', 'Review the Arista router configuration.

Arista MLS IP packets to GTSM enabled BGP peers are sent with the configured TTL value of 254.

router bgp NNN
 neighbor 10.1.12.2 ttl maximum-hops 2

If the Arista router is not configured to use GTSM for all Exterior Border Gateway Protocol peering sessions, this is a finding.'
  desc 'fix', 'Configure all Exterior Border Gateway Protocol peering sessions to use GTSM.

router bgp 65000
 neighbor 10.1.12.2 ttl maximum-hops 2'
  impact 0.3
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59715r882457_chk'
  tag severity: 'low'
  tag gid: 'V-256039'
  tag rid: 'SV-256039r882459_rule'
  tag stig_id: 'ARST-RT-000600'
  tag gtitle: 'SRG-NET-000362-RTR-000124'
  tag fix_id: 'F-59658r882458_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
