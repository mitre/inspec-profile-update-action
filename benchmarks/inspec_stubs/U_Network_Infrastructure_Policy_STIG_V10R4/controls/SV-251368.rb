control 'SV-251368' do
  title 'A deny-by-default security posture must be implemented for traffic entering and leaving the enclave.'
  desc 'To prevent malicious or accidental leakage of traffic, organizations must implement a deny-by-default security posture at the network perimeter.  Such rulesets prevent many malicious exploits or accidental leakage by restricting the traffic to only known sources and only those ports, protocols, or services that are permitted and operationally necessary.

Applications, protocols, TCP/UDP ports, and endpoints (specific hosts or networks) are identified and used to develop rulesets and access control lists to restrict traffic to and from an enclave.'
  desc 'check', 'Determine if a deny-by-default security posture has been implemented for both inbound and outbound traffic on the perimeter router or firewall.

If a deny-by-default security posture has not been implemented at the network perimeter, this is a finding.'
  desc 'fix', 'Implement a deny-by-default security posture on either the enclave perimeter router or firewall.'
  impact 0.7
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-54803r806057_chk'
  tag severity: 'high'
  tag gid: 'V-251368'
  tag rid: 'SV-251368r853653_rule'
  tag stig_id: 'NET0369'
  tag gtitle: 'NET0369'
  tag fix_id: 'F-54756r806058_fix'
  tag 'documentable'
  tag legacy: ['V-11796', 'SV-12294']
  tag cci: ['CCI-002080', 'CCI-002082', 'CCI-002398', 'CCI-002399']
  tag nist: ['CA-3 (5)', 'CA-3 (5)', 'SC-7 (9) (a)', 'SC-7 (9) (a)']
end
