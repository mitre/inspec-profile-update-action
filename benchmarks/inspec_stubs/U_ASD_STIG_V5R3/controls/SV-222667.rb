control 'SV-222667' do
  title 'Protections against DoS attacks must be implemented.'
  desc 'Known DoS threats documented in the threat model should be mitigated, to prevent DoS type attacks.'
  desc 'check', 'Ask the application representative for the threat model document.

Examine the threat model document and determine if DoS attacks are specified as a threat.

If there are no DoS threats identified in the threat model, the requirement is not applicable.

Verify the mitigations provided for DoS attacks are implemented from the threat model.

If mitigations for DoS attacks are identified in the threat model but are not implemented, this is a finding.'
  desc 'fix', 'Implement mitigations from the threat model for DOS attacks.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24337r493909_chk'
  tag severity: 'medium'
  tag gid: 'V-222667'
  tag rid: 'SV-222667r879887_rule'
  tag stig_id: 'APSC-DV-003320'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24326r493910_fix'
  tag 'documentable'
  tag legacy: ['SV-85035', 'V-70413']
  tag cci: ['CCI-002386']
  tag nist: ['SC-5']
end
