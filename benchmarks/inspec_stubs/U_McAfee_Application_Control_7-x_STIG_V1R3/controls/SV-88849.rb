control 'SV-88849' do
  title 'A McAfee Application Control written policy must be documented to outline the organization-specific variables for application whitelisting.'
  desc 'Enabling application whitelisting without adequate design and organization-specific requirements will either result in an implementation which is too relaxed or an implementation which causes denial of service to its user community. Documenting the specific requirements and trust model before configuring and deploying the McAfee Application Control software is mandatory.'
  desc 'check', 'Consult with the ISSO/ISSM to review the organizational-specific written policy for the McAfee Application Control software.

If no written policy exists, this is a finding.'
  desc 'fix', 'Document fully the written policy for the McAfee Application Control software, to include processes for password management, vetting application for whitelist/blocking, frequency of reviewing application whitelist, and settings for other requirements in this STIG.

Submit the written policy to be initially approved by and maintained by the Information System Security Officer/Information System Security Manager (ISSO/ISSM/AO) at that location.

Formalize a change control process to ensure changes to the written policy are made in a controlled manner. 

Formalize a review process requiring signed acceptance by the ISSO/ISSM/AO for any changes made to the written policy. 

If a formal Change Advisory Board (CAB) or Configuration Control Board (CCB) exists, the McAfee Application Control written policy must be under the CAB/CCB oversight.'
  impact 0.5
  ref 'DPMS Target McAfee Application Control 7.0 Managed Desktop'
  tag check_id: 'C-74229r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74175'
  tag rid: 'SV-88849r1_rule'
  tag stig_id: 'MCAC-PO-000100'
  tag gtitle: 'SRG-APP-000386'
  tag fix_id: 'F-80705r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end
