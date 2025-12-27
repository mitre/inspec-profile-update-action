control 'SV-254029' do
  title 'The Juniper Multicast Source Discovery Protocol (MSDP) router must be configured to authenticate all received MSDP packets.'
  desc 'MSDP peering with customer network routers presents additional risks to the core, whether from a rogue or misconfigured MSDP-enabled router. MSDP password authentication is used to validate each segment sent on the TCP connection between MSDP peers, protecting the MSDP session against the threat of spoofed packets being injected into the TCP connection stream.'
  desc 'check', 'Review the router configuration to determine if received MSDP packets are authenticated.

[edit protocols]
msdp {
    active-source-limit {
        maximum <1..1000000>;
        threshold <1..1000000>;
        log-warning <percent to log warning>;
    }
    <additional configuration>
    peer <address> {
        authentication-key "hashed PSK"; ## SECRET-DATA
    }
}

If the router does not require MSDP authentication, this is a finding.'
  desc 'fix', 'Ensure all MSDP packets received by an MSDP router are authenticated.

set protocols msdp active-source-limit maximum <1..1000000>
set protocols msdp active-source-limit threshold <1..1000000>
set protocols msdp active-source-limit log-warning <percent to log warning>
<additional configuration>
set protocols msdp peer <address> authentication-key <PSK>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57481r844118_chk'
  tag severity: 'medium'
  tag gid: 'V-254029'
  tag rid: 'SV-254029r844120_rule'
  tag stig_id: 'JUEX-RT-000570'
  tag gtitle: 'SRG-NET-000343-RTR-000002'
  tag fix_id: 'F-57432r844119_fix'
  tag 'documentable'
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
