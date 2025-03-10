control 'SV-68599' do
  title 'The ALG providing intermediary services for remote access communications traffic must ensure inbound and outbound traffic is monitored for compliance with remote access security policies.'
  desc "Automated monitoring of remote access traffic allows organizations to detect cyber attacks and also ensure ongoing compliance with remote access policies by inspecting connection activities of remote access capabilities.

Remote access methods include both unencrypted and encrypted traffic (e.g., web portals, web content filter, TLS and webmail). With inbound TLS inspection, the traffic must be inspected prior to being allowed on the enclave's web servers hosting TLS or HTTPS applications. With outbound traffic inspection, traffic must be inspected prior to being forwarded to destinations outside of the enclave, such as external email traffic."
  desc 'check', 'If the ALG does not serve as an intermediary for remote access traffic (e.g., web content filter, TLS and webmail), this is not applicable.

Verify the ALG is configured to inspect traffic or forward to a monitoring device for inspection prior to forwarding to inbound or outbound destinations.
Verify that the communications package is either forwarded or disallowed and that the process does not alter the original data payload that is forwarded to the destination application.

If the ALG does not ensure inbound and outbound traffic is monitored for compliance with remote access security policies, this is a finding.'
  desc 'fix', 'If intermediary services for remote access communications traffic are provided, configure the ALG to either provide content inspection for inbound and outbound traffic or route the traffic to be inspected for compliance with remote access security policies.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-54969r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54353'
  tag rid: 'SV-68599r1_rule'
  tag stig_id: 'SRG-NET-000061-ALG-000009'
  tag gtitle: 'SRG-NET-000061-ALG-000009'
  tag fix_id: 'F-59207r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
