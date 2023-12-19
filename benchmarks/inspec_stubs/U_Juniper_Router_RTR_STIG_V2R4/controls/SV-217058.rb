control 'SV-217058' do
  title 'The Juniper BGP router must be configured to reject route advertisements from BGP peers that do not list their autonomous system (AS) number as the first AS in the AS_PATH attribute.'
  desc 'Verifying the path a route has traversed will ensure the IP core is not used as a transit network for unauthorized or possibly even Internet traffic. All autonomous system boundary routers (ASBRs) must ensure updates received from eBGP peers list their AS number as the first AS in the AS_PATH attribute.'
  desc 'check', 'Review the router configuration to verify the router is configured to deny updates received from eBGP peers that do not list their AS number as the first AS in the AS_PATH attribute. Verify that the enforce-first-as command has been configured at the BGP or group hierarchy as shown in the example below:

protocols {
…
…
…
    bgp {
        enforce-first-as;

If the router is not configured to reject updates from peers that do not list their AS number as the first AS in the AS_PATH attribute, this is a finding.'
  desc 'fix', 'Configure the router to deny updates received from eBGP peers that do not list their AS number as the first AS in the AS_PATH attribute using the enforce-first-as command as shown in the example below:

[edit protocols bgp group]
set enforce-first-as'
  impact 0.3
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18287r297042_chk'
  tag severity: 'low'
  tag gid: 'V-217058'
  tag rid: 'SV-217058r604135_rule'
  tag stig_id: 'JUNI-RT-000530'
  tag gtitle: 'SRG-NET-000018-RTR-000006'
  tag fix_id: 'F-18285r297043_fix'
  tag 'documentable'
  tag legacy: ['SV-101111', 'V-90901']
  tag cci: ['CCI-000032']
  tag nist: ['AC-4 (8) (a)']
end
