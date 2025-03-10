control 'SV-253989' do
  title "The Juniper perimeter router must be configured to protect an enclave connected to an alternate gateway by using an inbound filter that only permits packets with destination addresses within the site's address space."
  desc "Enclaves with alternate gateway connections must take additional steps to ensure there is no compromise on the enclave network or NIPRNet. Without verifying the destination address of traffic coming from the site's alternate gateway, the perimeter router could be routing transit data from the internet into the NIPRNet. This could also make the perimeter router vulnerable to a denial-of-service (DoS) attack as well as provide a back door into the NIPRNet. The DoD enclave must ensure the ingress filter applied to external interfaces on a perimeter router connecting to an Approved Gateway is secure through filters permitting packets with a destination address belonging to the DoD enclave's address block."
  desc 'check', %q(This requirement is not applicable for the DODIN Backbone.

Review the configuration of each router interface connecting to an alternate gateway.

Verify each permit statement of the ingress filter only permits packets with destination addresses of the site's NIPRNet address space or a destination address belonging to the address block assigned by the alternate gateway network service provider. Verify each permit statement "from" stanza (filter match conditions) references either the "destination-address" or "destination-prefix-list" directive. Using prefix lists makes management easier because managing interior addresses must only be configured in one location (the prefix-list) vice many locations (each permitting filter term). For example:
[edit policy-options]
prefix-list inside_addresses-ipv4 {
    <IPv4 subnet / mask>;
}
prefix-list inside_addresses-ipv6 {
    <IPv6 subnet / prefix>;
}
[edit firewall]
family inet {
    filter inbound-ipv4 {
        <deny terms>;
        permit-term1 {
            from {
                <match conditions>;
                destination-prefix-list inside_addresses-ipv4;
            }
            then accept;
        }
        <additional permit terms with a destination address definition>
    }
}
family inet6 {
    filter inbound-ipv6 {
        <deny terms>;
        permit-term1 {
            from {
                <match conditions>;
                destination-prefix-list inside_addresses-ipv6;
            }
            then accept;
        }
        <additional permit terms with a destination address definition>
    }
}

Verify the filter is applied inbound on exterior-facing interfaces. For example:
[edit interfaces]
<interface name> {
    unit <number> {
        family inet {
            filter {
                input inbound-ipv4;
            }
            address <IPv4 address / mask>;
        }
        family inet6 {
            filter {
                input inbound-ipv6;
            }
            address <IPv6 address / prefix>;
        }
    }
}

Note: Some Juniper devices support both monolithic filters and filter lists. Filter lists separate each term, or set of terms, into a separate filter that is applied sequentially to an interface. If using filter lists, the keywords "input" or "output" change to "input-list" or "output-list". Verify the final list item is a deny-all filter.

If the ingress filter permits packets with addresses other than those specified, such as destination addresses of the site's NIPRNet address space or a destination address belonging to the address block assigned by the alternate gateway network service provider, this is a finding.)
  desc 'fix', "This requirement is not applicable for the DODIN Backbone.

Configure the ingress filter of the perimeter router connected to an alternate gateway to only permit packets with destination addresses of the site's NIPRNet address space or a destination address belonging to the address block assigned by the alternate gateway network service provider. For example:

set policy-options prefix-list inside_addresses-ipv4 <IPv4 subnet / mask>
set policy-options prefix-list inside_addresses-ipv6 <IPv6 subnet / prefix>

set firewall family inet filter inbound-ipv4 <deny terms>
set firewall family inet filter inbound-ipv4 <permit term> from <match conditions>
set firewall family inet filter inbound-ipv4 <permit term> from destination-prefix-list inside_addresses-ipv4
set firewall family inet filter inbound-ipv4 <permit term> then accept

set firewall family inet6 filter inbound-ipv6 <deny terms>
set firewall family inet6 filter inbound-ipv6 <permit term> from <match conditions>
set firewall family inet6 filter inbound-ipv6 <permit term> from destination-prefix-list inside_addresses-ipv6
set firewall family inet6 filter inbound-ipv6 <permit term> then accept"
  impact 0.7
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57441r843998_chk'
  tag severity: 'high'
  tag gid: 'V-253989'
  tag rid: 'SV-253989r844000_rule'
  tag stig_id: 'JUEX-RT-000170'
  tag gtitle: 'SRG-NET-000019-RTR-000008'
  tag fix_id: 'F-57392r843999_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
