control 'SV-215726' do
  title 'The BIG-IP APM module access policy profile must control remote access methods to virtual servers.'
  desc 'Remote access devices, such as those providing remote access to network devices and information systems, which lack automated control capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include broadband and wireless connections. Remote access methods include, for example, proxied remote encrypted traffic (e.g., TLS gateways, web content filters, and webmail proxies).

This requirement applies to ALGs providing remote access proxy services as part of its intermediary services (e.g., OWA or TLS gateway). ALGs that proxy remote access must be capable of taking enforcement action (i.e., blocking, restricting, or forwarding to an enforcement mechanism) if traffic monitoring reveals unauthorized activity.'
  desc 'check', 'If the BIG-IP APM module does not serve as an intermediary for remote access traffic (e.g., web content filter, TLS and webmail), this is not applicable.

Verify the BIG-IP APM module is configured to control remote access methods.

Verify the BIG-IP APM module is configured as follows:

Navigate to the BIG-IP System manager >> Access Policy >> Access Profiles.

Click "Edit..." in the "Access Policy" column for an Access Profile used for managing remote access.

Verify the Access Profile is configured to control remote access methods.

If the BIG-IP APM module is not configured to control remote access methods, this is a finding.'
  desc 'fix', 'If intermediary services for remote access communications traffic are provided, configure the BIG-IP APM module to control remote access methods.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Access Policy Manager 11.x'
  tag check_id: 'C-16919r290424_chk'
  tag severity: 'medium'
  tag gid: 'V-215726'
  tag rid: 'SV-215726r557355_rule'
  tag stig_id: 'F5BI-AP-000153'
  tag gtitle: 'SRG-NET-000313-ALG-000010'
  tag fix_id: 'F-16917r290425_fix'
  tag 'documentable'
  tag legacy: ['SV-74473', 'V-60043']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
