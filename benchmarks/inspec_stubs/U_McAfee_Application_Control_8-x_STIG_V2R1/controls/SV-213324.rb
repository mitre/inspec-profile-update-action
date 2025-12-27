control 'SV-213324' do
  title 'The organizations written policy must include a process for how whitelisted applications are deemed to be allowed.'
  desc 'Enabling application whitelisting without adequate design and organization-specific requirements will either result in an implementation which is too relaxed or an implementation which causes denial of service to its user community. Documenting the specific requirements and trust model before configuring and deploying the McAfee Application Control software is mandatory.'
  desc 'check', 'Consult with the ISSO/ISSM to review the organizational-specific written policy for the McAfee Application Control software.

Verify the written policy includes a process for how applications are vetted and deemed to be allowed.

If no written policy exists, this is a finding.

If written policy does not include a process for vetting applications before allowing them, this is a finding.'
  desc 'fix', 'Follow the formal change and acceptance process to update the written policy to include a process for how applications are vetted and deemed to be allowed.'
  impact 0.5
  ref 'DPMS Target McAfee Application Control 8.x'
  tag check_id: 'C-14552r309069_chk'
  tag severity: 'medium'
  tag gid: 'V-213324'
  tag rid: 'SV-213324r506897_rule'
  tag stig_id: 'MCAC-PO-000109'
  tag gtitle: 'SRG-APP-000386'
  tag fix_id: 'F-14550r309070_fix'
  tag 'documentable'
  tag legacy: ['SV-88879', 'V-74205']
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end
