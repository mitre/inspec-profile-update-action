control 'SV-207190' do
  title 'The TLS VPN Gateway must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during transmission for remote access connections.'
  desc 'Using older unauthorized versions or incorrectly configuring protocol negotiation makes the gateway vulnerable to known and unknown attacks that exploit vulnerabilities in this protocol.

NIST SP 800-52 Rev2 provides guidance for client negotiation on either DoD-only or public-facing servers.'
  desc 'check', 'Verify the TLS VPN Gateway is configured to use  TLS 1.2 or higher to protect the confidentiality of sensitive data during transmission.

If the TLS VPN Gateway does not use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during transmission, this is a finding.'
  desc 'fix', 'Configure the TLS VPN Gateway to use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data for transmission.'
  impact 0.7
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7450r378191_chk'
  tag severity: 'high'
  tag gid: 'V-207190'
  tag rid: 'SV-207190r803417_rule'
  tag stig_id: 'SRG-NET-000062-VPN-000200'
  tag gtitle: 'SRG-NET-000062'
  tag fix_id: 'F-7450r378192_fix'
  tag 'documentable'
  tag legacy: ['V-97053', 'SV-106191']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
