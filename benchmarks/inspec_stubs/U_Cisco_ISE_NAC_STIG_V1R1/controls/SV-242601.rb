control 'SV-242601' do
  title 'The Cisco ISE must authenticate all endpoint devices before establishing a connection and proceeding with posture assessment.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. However, failure to authenticate an endpoint does not need to result in connection termination or preclude compliance assessment. This is particularly true for unmanaged systems or when the Cisco ISE is performing network discovery.

Authentication methods for NAC on access switches are MAC Authentication Bypass (MAB), or 802.1x.'
  desc 'check', 'Verify that the authorization policies have either "deny-access" or restricted access on their default authorization policy set. 

1. Work Centers >> Network Access >> Policy Sets.
2. Choose ">" on the desired policy set.
3. Expand Authorization Policy.

If the default authorization policy within each policy set has "deny-access" or restricted access, this is not a finding.'
  desc 'fix', 'Configure each policy set so that authorization policies have either "deny-access" or restricted access on their default authorization policy set. 

1. Work Centers >> Network Access >> Policy Sets.
2. Choose ">" on the desired policy set.
3. Expand Authorization Policy.

On the default authorization rule, select "Deny-Access" or a result that is configured for a restricted VLAN, Access Control List, Scalable Group Tag, or any combination of these used to restrict access.'
  impact 0.5
  ref 'DPMS Target Cisco ISE NAC'
  tag check_id: 'C-45876r714111_chk'
  tag severity: 'medium'
  tag gid: 'V-242601'
  tag rid: 'SV-242601r714113_rule'
  tag stig_id: 'CSCO-NC-000270'
  tag gtitle: 'SRG-NET-000343-NAC-001460'
  tag fix_id: 'F-45833r714112_fix'
  tag 'documentable'
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
