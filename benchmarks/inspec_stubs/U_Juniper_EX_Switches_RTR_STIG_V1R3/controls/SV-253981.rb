control 'SV-253981' do
  title 'The Juniper router configured for MSDP must limit the amount of source-active messages it accepts on per-peer basis.'
  desc 'To reduce any risk of a denial-of-service (DoS) attack from a rogue or misconfigured MSDP router, the router must be configured to limit the number of source-active messages it accepts from each peer.'
  desc 'check', 'Review the router configuration to determine if it is configured to limit the amount of source-active messages it accepts on a per-peer basis.

[edit protocols]
msdp {
    active-source-limit {
        maximum <1..1000000>;
        threshold <1..1000000>;
        log-warning <percent to log warning>;
    }
    local-address <lo0 address>;
    <additional configuration>
    peer <address> {
        active-source-limit {
            maximum <1..1000000>;
            threshold <1..1000000>;
            log-warning <percent to log warning>;
        }
        authentication-key "hashed PSK"; ## SECRET-DATA
    }
}
Note: Both the global, and the peer limit, are applied to every MSDP peer, and Junos applies the most restrictive limit. The maximum value sets the upper limit for source-active messages and the threshold value determines when Junos begins Random Early Detection (RED) dropping to alleviate congestion. The log-warning value is a percent where Junos begins generating syslog messages.

If the router is not configured to limit the source-active messages it accepts, this is a finding.'
  desc 'fix', 'Configure the MSDP router to limit the amount of source-active messages it accepts from each peer.

set protocols msdp active-source-limit maximum <1..1000000>
set protocols msdp active-source-limit threshold <1..1000000>
set protocols msdp active-source-limit log-warning <percent to log warning>
<additional configuration>
set protocols msdp peer <address> active-source-limit maximum <1..1000000>
set protocols msdp peer <address> active-source-limit threshold <1..1000000>
set protocols msdp peer <address> active-source-limit log-warning <percent to log warning>'
  impact 0.3
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57433r843974_chk'
  tag severity: 'low'
  tag gid: 'V-253981'
  tag rid: 'SV-253981r843976_rule'
  tag stig_id: 'JUEX-RT-000090'
  tag gtitle: 'SRG-NET-000018-RTR-000009'
  tag fix_id: 'F-57384r843975_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
