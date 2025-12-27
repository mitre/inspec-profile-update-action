control 'SV-242192' do
  title 'The TPS must protect against or limit the effects of known types of Denial of Service (DoS) attacks by employing signatures.'
  desc 'If the network does not provide safeguards against DoS attack, network resources will be unavailable to users. 

Installation of TPS detection and prevention components (i.e., sensors) at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks and monitoring for anomalies in traffic volume, type, or protocol usage.

Detection components that use signatures can detect known attacks by using known attack signatures. Signatures are usually obtained from and updated by the IDPS component vendor. These attacks include SYN-flood, ICMP-flood, and Land Attacks.

This requirement applies to the communications traffic functionality of the IDPS as it pertains to handling communications traffic, rather than to the IDPS device itself.'
  desc 'check', %q(1. In the Trend Micro SMS, navigate to "Profiles" and "Inspection Profiles" and select the organization's profile. 
2. If there is not one configured, select "Default". 
3. Click "Search". 
4. Under "Filter criteria", select the Filter Category "Traffic Normalization, Exploits, and Vulnerabilities", select the "Filter Name" section and type "ddos".

If the following filter names produced in the search list are not set to Block+Notify, this is a finding.

Note: If the site has set up a security profile (i.e., not using the default profile), then this should be inspected using the site's SSP for compliance.)
  desc 'fix', %q(1. In the Trend Micro SMS, navigate to "Profiles" and "Inspection Profiles" and select the organization's profile. 
2. If there is not one configured, select "Default". 
3. Click "Search". 
4. Select the Filter Category "Traffic Normalization, Exploits, and Vulnerabilities". Select the "Filter Name" section and type "ddos".
5. Set all the items in the search to Block+Notify.

Note: If the site has set up a security profile (i.e., not using the default profile), then this should be inspected using the site's SSP for compliance.)
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint IDPS'
  tag check_id: 'C-45467r838220_chk'
  tag severity: 'medium'
  tag gid: 'V-242192'
  tag rid: 'SV-242192r840191_rule'
  tag stig_id: 'TIPP-IP-000270'
  tag gtitle: 'SRG-NET-000362-IDPS-00198'
  tag fix_id: 'F-45425r840190_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
