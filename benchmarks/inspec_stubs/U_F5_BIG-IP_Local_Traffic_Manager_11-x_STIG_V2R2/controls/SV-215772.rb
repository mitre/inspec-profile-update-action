control 'SV-215772' do
  title 'The BIG-IP Core implementation providing intermediary services for remote access communications traffic must control remote access methods to virtual servers.'
  desc 'Remote access devices, such as those providing remote access to network devices and information systems, which lack automated control capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include broadband and wireless connections. Remote access methods include, for example, proxied remote encrypted traffic (e.g., TLS gateways, web content filters, and webmail proxies).

This requirement applies to ALGs providing remote access proxy services as part of its intermediary services (e.g., OWA or TLS gateway). ALGs that proxy remote access must be capable of taking enforcement action (i.e., blocking, restricting, or forwarding to an enforcement mechanism) if traffic monitoring reveals unauthorized activity.'
  desc 'check', 'If the BIG-IP Core does not serve as an intermediary for remote access traffic (e.g., web content filter, TLS, and webmail) for virtual servers, this is not applicable.

When intermediary services for remote access communications are provided, verify the BIG-IP Core is configured to control remote access methods.

Verify Virtual Server(s) in the BIG-IP LTM module are configured with an APM policy to control remote access methods.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify.

Verify under "Access Policy" section that "Access Policy" has been set to use an APM access policy that controls remote access methods to virtual servers.

If the BIG-IP Core does not control remote access methods, this is a finding.'
  desc 'fix', 'If intermediary services for remote access communications traffic are provided, configure the BIG-IP Core as follows:

Configure a policy in the BIG-IP APM module to control remote access methods.

Apply APM policy to the applicable Virtual Server(s) in the BIG-IP LTM module to control remote access methods to virtual servers.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16964r291129_chk'
  tag severity: 'medium'
  tag gid: 'V-215772'
  tag rid: 'SV-215772r831460_rule'
  tag stig_id: 'F5BI-LT-000153'
  tag gtitle: 'SRG-NET-000313-ALG-000010'
  tag fix_id: 'F-16962r291130_fix'
  tag 'documentable'
  tag legacy: ['V-60325', 'SV-74755']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
