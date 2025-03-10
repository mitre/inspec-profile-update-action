control 'SV-242195' do
  title 'The TPS must block malicious ICMP packets by properly configuring ICMP signatures and rules.'
  desc 'Internet Control Message Protocol (ICMP) messages are used to provide feedback about problems in the network. These messages are sent back to the sender to support diagnostics. However, some messages can also provide host information, network topology, and a covert channel that may be exploited by an attacker.

Given the prevalence of ICMP traffic on the network, monitoring for malicious ICMP traffic would be cumbersome. Vendors provide signatures and rules which filter for known ICMP traffic exploits.'
  desc 'check', %q(1. In the Trend Micro SMS, navigate to "Profiles" and "Inspection Profiles" and select the organization's profile. 
2. If there is not one configured, select "Default". 
3. Click "Search". 
4. Under "Filter criteria", select the Filter Category "Traffic Normalization, Exploits, and Vulnerabilities". Select the "Filter Name" section and type "ICMP".

If the following filter names produced in the search list are not set to Block+Notify, this is a finding.

Note: If the site has set up a security profile (i.e., not using the default profile), then this should be inspected using the site's SSP for compliance.)
  desc 'fix', %q(1. In the Trend Micro SMS, navigate to "Profiles" and "Inspection Profiles" and select the organization's profile. 
2. If there is not one configured, select "Default". 
3. Click "Search". 
4. Select the Filter Category "Traffic Normalization, Exploits, and Vulnerabilities". Select the "Filter Name" section and type "ICMP".
5. Set all the items in the search to Block+Notify.

Note: If the site has set up a security profile (i.e., not using the default profile), then this should be inspected using the site's SSP for compliance.)
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint IDPS'
  tag check_id: 'C-45470r838226_chk'
  tag severity: 'medium'
  tag gid: 'V-242195'
  tag rid: 'SV-242195r840193_rule'
  tag stig_id: 'TIPP-IP-000300'
  tag gtitle: 'SRG-NET-000273-IDPS-00204'
  tag fix_id: 'F-45428r840192_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
