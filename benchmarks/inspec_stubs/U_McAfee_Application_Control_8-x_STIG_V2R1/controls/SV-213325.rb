control 'SV-213325' do
  title 'The organizations written policy must include procedures for how often the whitelist of allowed applications is reviewed.'
  desc 'Enabling application whitelisting without adequate design and organization-specific requirements will either result in an implementation which is too relaxed or an implementation which causes denial of service to its user community. Documenting the specific requirements and trust model before configuring and deploying the McAfee Application Control software is mandatory.'
  desc 'check', 'Consult with the ISSO/ISSM to review the organizational-specific written policy for the McAfee Application Control software.

Verify the written policy includes a process for how often the application whitelist is reviewed.

If no written policy exists, this is a finding.

If written policy does not include a process for how often the application whitelist is reviewed, this is a finding.'
  desc 'fix', 'Follow the formal change and acceptance process to update the written policy to include a process for how often the application whitelist is reviewed.'
  impact 0.5
  ref 'DPMS Target McAfee Application Control 8.x'
  tag check_id: 'C-14553r309072_chk'
  tag severity: 'medium'
  tag gid: 'V-213325'
  tag rid: 'SV-213325r506897_rule'
  tag stig_id: 'MCAC-PO-000110'
  tag gtitle: 'SRG-APP-000386'
  tag fix_id: 'F-14551r309073_fix'
  tag 'documentable'
  tag legacy: ['V-74207', 'SV-88881']
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end
