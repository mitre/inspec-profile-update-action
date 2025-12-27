control 'SV-242190' do
  title 'The TPS must block any prohibited mobile code at the enclave boundary when it is detected.'
  desc "Mobile code is defined as software modules obtained from remote systems, transferred across a network, and then downloaded and executed on a local system without explicit installation or execution by the recipient. Examples of mobile code include JavaScript, VBScript, Java applets, ActiveX controls, Flash animations, Shockwave videos, and macros embedded within Microsoft Office documents. Mobile code can be exploited to attack a host. It can be sent as an e-mail attachment or embedded in other file formats not traditionally associated with executable code. 

While the IDPS cannot replace the anti-virus and host-based IDS (HIDS) protection installed on the network's endpoints, vendor- or locally- created sensor rules can be implemented, which provide preemptive defense against both known and zero-day vulnerabilities. Many of the protections may provide defenses before vulnerabilities are discovered and rules or blacklist updates are distributed by anti-virus or malicious code solution vendors.

To block known prohibited mobile code or approved mobile code that violates permitted usage requirements, the IDPS must implement policy filters, rules, signatures, and anomaly analysis."
  desc 'check', %q(1. In the Trend Micro SMS, navigate to "Profiles" and "Inspection Profiles" and select the organization's profile. 
2. If there is not one configured, select "Default". 
3. Click "Edit Details". Ensure the deployment mode of "Security-Optimized" is selected. The security-optimized deployment mode ensures all strict DoD vulnerabilities are blocked and alerted upon. 
4. Navigate to "Profile Overview" and ensure the action set for each category is set to "Recommended". The recommended action set is set to ensure all suspicious and vulnerable traffic is blocked and alerted upon. 

If the "security-optimized" deployment mode is not configured, this is a finding.)
  desc 'fix', %q(1. In the Trend Micro SMS, navigate to "Profiles" and "Inspection Profiles" and select the organization's profile. 
2. If there is not one configured, select "Default". 
3. Click "Edit Details". Select the deployment mode of "Security-Optimized". The security-optimized deployment mode ensures all strict DoD vulnerabilities are blocked and alerted upon. 
4. Navigate to "Profile Overview", and select the action set for each category to "Recommended". The recommended action set is set to ensure all suspicious and vulnerable traffic is blocked and alerted upon.)
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint IDPS'
  tag check_id: 'C-45465r710111_chk'
  tag severity: 'medium'
  tag gid: 'V-242190'
  tag rid: 'SV-242190r710113_rule'
  tag stig_id: 'TIPP-IP-000250'
  tag gtitle: 'SRG-NET-000229-IDPS-00163'
  tag fix_id: 'F-45423r710112_fix'
  tag 'documentable'
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
