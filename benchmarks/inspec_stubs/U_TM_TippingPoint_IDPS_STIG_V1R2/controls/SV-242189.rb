control 'SV-242189' do
  title 'The TPS must detect, at a minimum, mobile code that is unsigned or exhibiting unusual behavior, has not undergone a risk assessment, or is prohibited for use based on a risk assessment.'
  desc "Mobile code is defined as software modules obtained from remote systems, transferred across a network, and then downloaded and executed on a local system without explicit installation or execution by the recipient. Examples of mobile code include JavaScript, VBScript, Java applets, ActiveX controls, Flash animations, Shockwave videos, and macros embedded within Microsoft Office documents. Mobile code can be exploited to attack a host. It can be sent as an e-mail attachment or embedded in other file formats not traditionally associated with executable code. 

While the TPS cannot replace the anti-virus and host-based IDS (HIDS) protection installed on the network's endpoints, vendor or locally created sensor rules can be implemented, which provide preemptive defense against both known and zero-day vulnerabilities. Many of the protections may provide defenses before vulnerabilities are discovered and rules or blacklist updates are distributed by anti-virus or malicious code solution vendors.

To monitor for and detect known prohibited mobile code or approved mobile code that violates permitted usage requirements, the TPS must implement policy filters, rules, signatures, and anomaly analysis."
  desc 'check', %q(1. In the Trend Micro SMS, navigate to "Profiles" and "Inspection Profiles" and select the organization's profile.
2. If there is not one configured, select "Default". 
3. Click "Edit Details". 
4. Ensure the deployment mode of "default" is selected. The default deployment mode ensures all strict DoD vulnerabilities are blocked and alerted upon. 
5. Navigate to "Profile Overview" and ensure the action set for each category is set to "Recommended". The recommended action set is set to ensure all suspicious and vulnerable traffic is blocked and alerted upon. 

If the "default" deployment mode is not configured, this is a finding.

Note: If the site has set up a security profile (i.e., not using the default profile), then this should be inspected using the site's SSP for compliance.)
  desc 'fix', %q(1. In the Trend Micro SMS, navigate to "Profiles" and "Inspection Profiles" and select the organization's profile. 
2. If there is not one configured, select "Default". 
3. Click "Edit Details". Select the deployment mode of "default". The default deployment mode ensures all strict DoD vulnerabilities are blocked and alerted upon. 
4. Navigate to "Profile Overview", and select the action set for each category to "Recommended". The recommended action set is set to ensure all suspicious and vulnerable traffic is blocked and alerted upon.

Note: If the site has set up a security profile (i.e., not using the default profile), then this should be inspected using the site's SSP for compliance.)
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint IDPS'
  tag check_id: 'C-45464r838214_chk'
  tag severity: 'medium'
  tag gid: 'V-242189'
  tag rid: 'SV-242189r839149_rule'
  tag stig_id: 'TIPP-IP-000240'
  tag gtitle: 'SRG-NET-000228-IDPS-00196'
  tag fix_id: 'F-45422r838215_fix'
  tag 'documentable'
  tag cci: ['CCI-001166']
  tag nist: ['SC-18 (1)']
end
