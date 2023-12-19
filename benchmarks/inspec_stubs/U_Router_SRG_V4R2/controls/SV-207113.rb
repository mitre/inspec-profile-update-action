control 'SV-207113' do
  title 'The perimeter router must be configured to protect an enclave connected to an alternate gateway by using an inbound filter that only permits packets with destination addresses within the sites address space.'
  desc "Enclaves with alternate gateway connections must take additional steps to ensure there is no compromise on the enclave network or NIPRNet. Without verifying the destination address of traffic coming from the site's alternate gateway, the perimeter router could be routing transit data from the Internet into the NIPRNet. This could also make the perimeter router vulnerable to a denial-of-service (DoS) attack as well as provide a back door into the NIPRNet. The DoD enclave must ensure the ingress filter applied to external interfaces on a perimeter router connecting to an Approved Gateway is secure through filters permitting packets with a destination address belonging to the DoD enclave's address block."
  desc 'check', "This requirement is not applicable for the DoDIN Backbone.

Review the configuration of each router interface connecting to an alternate gateway.

Verify each permit statement of the ingress filter only permits packets with destination addresses of the site's NIPRNet address space or a destination address belonging to the address block assigned by the alternate gateway network service provider.

If the ingress filter permits packets with addresses other than those specified, such as destination addresses of the site's NIPRNet address space or a destination address belonging to the address block assigned by the alternate gateway network service provider, this is a finding."
  desc 'fix', "This requirement is not applicable for the DoDIN Backbone.

Configure the ingress filter of the perimeter router connected to an alternate gateway to only permit packets with destination addresses of the site's NIPRNet address space or a destination address belonging to the address block assigned by the alternate gateway network service provider."
  impact 0.7
  ref 'DPMS Target Router'
  tag check_id: 'C-7374r382232_chk'
  tag severity: 'high'
  tag gid: 'V-207113'
  tag rid: 'SV-207113r604135_rule'
  tag stig_id: 'SRG-NET-000019-RTR-000008'
  tag gtitle: 'SRG-NET-000019'
  tag fix_id: 'F-7374r382233_fix'
  tag 'documentable'
  tag legacy: ['SV-92947', 'V-78241']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
