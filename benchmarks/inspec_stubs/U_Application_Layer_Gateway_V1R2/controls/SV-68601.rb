control 'SV-68601' do
  title 'The ALG providing intermediary services for remote access communications traffic must control remote access methods.'
  desc 'Remote access devices, such as those providing remote access to network devices and information systems, which lack automated control capabilities, increase risk and makes remote user access management difficult at best.

Remote access is access to DoD-nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include broadband and wireless connections. Remote access methods include, for example, proxied remote encrypted traffic (e.g., TLS gateways, web content filters, and webmail proxies).

This requirement applies to ALGs providing remote access proxy services as part of its intermediary services (e.g., OWA or TLS gateway). ALGs that proxy remote access must be capable of taking enforcement action (i.e., blocking, restricting, or forwarding to an enforcement mechanism) if traffic monitoring reveals unauthorized activity.'
  desc 'check', 'If the ALG does not serve as an intermediary for remote access traffic (e.g., web content filter, TLS and webmail), this is not applicable.

Verify the ALG is configured to control remote access methods.

If the ALG does not control remote access methods, this is a finding.'
  desc 'fix', 'If intermediary services for remote access communications traffic are provided, configure the ALG to control remote access methods.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-54971r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54355'
  tag rid: 'SV-68601r1_rule'
  tag stig_id: 'SRG-NET-000313-ALG-000010'
  tag gtitle: 'SRG-NET-000313-ALG-000010'
  tag fix_id: 'F-59209r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
