control 'SV-242600' do
  title 'The Cisco ISE must deny network connection for endpoints that cannot be authenticated using an approved method.'
  desc 'Without identifying devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Identification failure does not need to result in connection termination or preclude compliance assessment. This is particularly true for unmanaged systems or when the Cisco ISE is performing network discovery.'
  desc 'check', 'Verify that the authorization policies have either "deny-access" or restricted access on their default authorization policy set. 

1. Work Centers >> Network Access >> Policy Sets.
2. Choose ">" on the desired policy set.
3. Expand Authorization Policy.

If the default authorization policy within each policy set has "deny-access" or restricted access, this is not a finding.'
  desc 'fix', 'Configure each policy set so that authorization policies have either "deny-access" or restricted access on their default authorization policy set. 

1. Work Centers >> Network Access >> Policy Sets.
2. Choose ">" on the desired policy set.
3. Expand Authorization Policy.

On the default authorization rule, select "Deny-Access" or a result that is configured for a restricted VLAN, ACL, SGT, or any combination of these used to restrict the access.'
  impact 0.5
  ref 'DPMS Target Cisco ISE NAC'
  tag check_id: 'C-45875r714108_chk'
  tag severity: 'medium'
  tag gid: 'V-242600'
  tag rid: 'SV-242600r714110_rule'
  tag stig_id: 'CSCO-NC-000260'
  tag gtitle: 'SRG-NET-000148-NAC-000620'
  tag fix_id: 'F-45832r714109_fix'
  tag 'documentable'
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
