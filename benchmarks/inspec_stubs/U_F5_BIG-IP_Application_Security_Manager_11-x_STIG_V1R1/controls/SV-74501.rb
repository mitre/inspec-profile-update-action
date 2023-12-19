control 'SV-74501' do
  title 'The BIG-IP ASM module must be configured to update malicious code protection mechanisms and signature definitions when providing content filtering to virtual servers for whenever new releases are available in accordance with organizational configuration management policy and procedures.'
  desc 'Malicious code protection mechanisms include, but are not limited to, anti-virus and malware detection software. In order to minimize any potential negative impact to the organization caused by malicious code, malicious code must be identified and eradicated. Malicious code includes viruses, worms, Trojan horses, and Spyware.

This requirement is limited to ALGs, web content filters, and packet inspection firewalls that perform malicious code detection as part of their functionality.'
  desc 'check', 'If the BIG-IP ASM module is not used to support content filtering as part of the traffic management functions of the BIG-IP Core, this is not applicable.

When content filtering is performed as part of the traffic management functionality, verify the BIG-IP ASM module is configured to update malicious code protection mechanisms and signature definitions whenever new releases are available in accordance with organizational configuration management policies and procedures.

Verify the BIG-IP ASM module is configured to update malicious code protection mechanisms and signature definitions when providing content filtering to virtual servers for whenever new releases are available in accordance with organizational configuration management policies and procedures.

Navigate to the BIG-IP System manager >> Security >> Options >> Application Security >> Attack Signatures >> Attack Signature Updates.

Review the following settings to confirm compliance with organizational configuration management policies and procedures:

Update Mode is set to "Manual", unless defined differently by the Organization.

Delivery Mode is set to "Automatic", unless defined differently by the Organization.

Verify that "Auto Apply New Signatures Configurations After Update" is NOT "Enabled", unless defined differently by the Organization.

If the BIG-IP ASM module does not update malicious code protection mechanisms and signature definitions whenever new releases are available in accordance with organizational configuration management policies and procedures, this is a finding.'
  desc 'fix', 'If the BIG-IP Core performs content filtering as part of the traffic management functionality, configure the BIG-IP ASM module to update malicious code protection mechanisms and signature definitions whenever new releases are available in accordance with organizational configuration management policies and procedures.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP ASM 11.x'
  tag check_id: 'C-60751r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60071'
  tag rid: 'SV-74501r1_rule'
  tag stig_id: 'F5BI-AS-000109'
  tag gtitle: 'SRG-NET-000246-ALG-000132'
  tag fix_id: 'F-65481r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001240']
  tag nist: ['SI-3 b']
end
