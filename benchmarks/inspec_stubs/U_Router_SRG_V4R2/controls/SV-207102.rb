control 'SV-207102' do
  title 'The BGP router must be configured to reject route advertisements from BGP peers that do not list their autonomous system (AS) number as the first AS in the AS_PATH attribute.'
  desc 'Verifying the path a route has traversed will ensure the IP core is not used as a transit network for unauthorized or possibly even Internet traffic. All autonomous system boundary routers (ASBRs) must ensure updates received from eBGP peers list their AS number as the first AS in the AS_PATH attribute.'
  desc 'check', 'Review the router configuration to verify the router is configured to deny updates received from eBGP peers that do not list their AS number as the first AS in the AS_PATH attribute.

If the router is not configured to reject updates from peers that do not list their AS number as the first AS in the AS_PATH attribute, this is a finding.'
  desc 'fix', 'Configure all ASBRs to deny updates received from eBGP peers that do not list their AS number as the first AS in the AS_PATH attribute.'
  impact 0.3
  ref 'DPMS Target Router'
  tag check_id: 'C-7363r382151_chk'
  tag severity: 'low'
  tag gid: 'V-207102'
  tag rid: 'SV-207102r604135_rule'
  tag stig_id: 'SRG-NET-000018-RTR-000006'
  tag gtitle: 'SRG-NET-000018'
  tag fix_id: 'F-7363r382152_fix'
  tag 'documentable'
  tag legacy: ['SV-92983', 'V-78277']
  tag cci: ['CCI-000032']
  tag nist: ['AC-4 (8) (a)']
end
