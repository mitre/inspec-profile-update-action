control 'SV-217097' do
  title 'The Juniper Multicast Source Discovery Protocol (MSDP) router must be configured to limit the amount of source-active messages it accepts on per-peer basis.'
  desc 'To reduce any risk of a denial-of-service (DoS) attack from a rogue or misconfigured MSDP router, the router must be configured to limit the number of source-active messages it accepts from each peer.'
  desc 'check', 'Review the router configuration to determine if it is configured to limit the amount of source-active messages it accepts on a per-peer basis.

protocols {
    …
    …
    …
    }
    msdp {
        export SA_EXPORT;
        import SA_IMPORT;
        group AS25 {
            peer x.x.x.x {
                active-source-limit {
                    maximum nnn;
                }

If the router is not configured to limit the source-active messages it accepts, this is a finding.'
  desc 'fix', 'Configure the router to limit the amount of source-active messages it accepts from each peer.

[edit protocols msdp group AS25 peer x.x.x.x]
set active-source-limit maximum nnn'
  impact 0.3
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18326r297159_chk'
  tag severity: 'low'
  tag gid: 'V-217097'
  tag rid: 'SV-217097r639663_rule'
  tag stig_id: 'JUNI-RT-000930'
  tag gtitle: 'SRG-NET-000018-RTR-000009'
  tag fix_id: 'F-18324r297160_fix'
  tag 'documentable'
  tag legacy: ['SV-101187', 'V-90977']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
