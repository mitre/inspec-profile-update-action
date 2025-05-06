control 'SV-251348' do
  title 'Encapsulated and/or encrypted traffic received from another enclave must not bypass the network perimeter defense without being terminated and inspected before entering the enclaves private network.'
  desc "Allowing encapsulated traffic to bypass the enclave's network perimeter without being filtered and inspected leaves the enclave vulnerable to malicious traffic that could result in compromise and denial of service. The destination of these packets could be servers that provide mission critical services and data."
  desc 'check', "Review network device configurations and topology diagrams to validate encapsulated traffic received from other enclaves terminate at the perimeter for filtering and content inspection. If the tunnel is terminated on a VPN gateway, validate the traffic is inspected by a firewall and IDPS before gaining access to the private network.

If the tunnel is being provided by the perimeter router with a direct connection to the tenant's perimeter router, then the perimeter router (of the enclave providing the transient service) must be configured (examples: policy based routing or VRF bound to this interface with only a default route pointing out) to insure all traffic received by this connecting interface is forwarded directly to the NIPR/SIPR interface regardless of destination.  If this isn't being done then the connecting interface will have to be treated as an external interface with all the applicable checks.

Secured connections such as SSL or TLS which are used for remote access, secure web access, etc. is also applicable to this rule. These types of connections like the other types above must terminate at the enclave perimeter, enclave DMZ, or an enclave service network for filtering and content inspection before passing into the enclave's private network.

If the tunnels do not meet any of the criteria above and bypass the enclave's perimeter without filtering and inspection, this is a finding.

Note: This vulnerability is not applicable for any VPN connectivity between multiple sites of the same enclave, nor is it applicable for VPN remote access to the enclave. For theses deployments, the implementation must be compliant with all requirements specified within the VPN SRG."
  desc 'fix', "Move tunnel decapsulation to a secure end-point at the enclave's perimeter for filtering and inspection."
  impact 0.7
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-54783r819075_chk'
  tag severity: 'high'
  tag gid: 'V-251348'
  tag rid: 'SV-251348r819076_rule'
  tag stig_id: 'NET-TUNL-026'
  tag gtitle: 'NET-TUNL-026'
  tag fix_id: 'F-54736r805998_fix'
  tag 'documentable'
  tag legacy: ['V-14737', 'SV-15493']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
