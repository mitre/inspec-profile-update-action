control 'SV-74497' do
  title 'The BIG-IP ASM module supporting intermediary services for remote access communications traffic must ensure inbound traffic is monitored for compliance with remote access security policies.'
  desc "Automated monitoring of remote access traffic allows organizations to detect cyber attacks and also ensure ongoing compliance with remote access policies by inspecting connection activities of remote access capabilities.

Remote access methods include both unencrypted and encrypted traffic (e.g., web portals, web content filter, TLS, and webmail). With inbound TLS inspection, the traffic must be inspected prior to being allowed on the enclave's web servers hosting TLS or HTTPS applications. 

Remote access security policies provide the guidance and define the traffic that will be monitored.  These policies consist of local policies, organizational policies, and DoD policies."
  desc 'check', 'If the BIG-IP ASM module does not support intermediary services for remote access traffic (e.g., web content filter, TLS, and webmail) for virtual servers, this is not applicable.

When the BIG-IP ASM module is used to support intermediary services for remote access communications traffic to virtual servers, verify the security policy is configured as follows:

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select the applicable Virtual Servers(s) from the list to verify.

Navigate to the Security >> Policies tab.

Verify an ASM policy is assigned and Enabled for "Application Security Policy".

Verify configuration of the identified ASM policy:

Navigate to the BIG-IP System manager >> Security >> Application Security >> Security Policies.

Review the list under "Active Security Policies" for a security policy that monitors inbound traffic for compliance with remote access security policies. 

Verify "Enforcement Mode" is set to "Transparent" or "Blocking" in accordance with the requirements for the applicable virtual server.

If the BIG-IP ASM module is not configured with a policy to monitor inbound traffic for compliance with remote access security policies and applied to the applicable virtual servers, this is a finding.'
  desc 'fix', 'If intermediary services for remote access communications traffic for virtual servers is supported by the BIG-IP ASM module, configure an ASM security policy to monitor inbound traffic for compliance with remote access security policies, to be applied to the applicable virtual servers in the BIG-IP LTM module.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP ASM 11.x'
  tag check_id: 'C-60747r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60067'
  tag rid: 'SV-74497r1_rule'
  tag stig_id: 'F5BI-AS-000031'
  tag gtitle: 'SRG-NET-000061-ALG-000009'
  tag fix_id: 'F-65477r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
