control 'SV-20126' do
  title 'A Secure WLAN (SWLAN) connected to the SIPRNet must have a SIPRNet connection approval package must be on file with the Classified Connection Approval Office (CCAO).'
  desc 'The CCAO approval process provides assurance that the SWLAN use is appropriate and does not introduce unmitigated risks into the SIPRNET.'
  desc 'check', 'Review documentation.
- Verify the SWLAN system SCAO approval documentation exists and has been approved and has a SIPRNet or NIPRNet Interim Approval to Operate (IATO) or Approval to Operate (ATO) in GIAP database.
- Verify the SWLAN system is included in the SSAA/SSP and is signed by the DAA.
Mark as a finding if requirements are not met.'
  desc 'fix', 'Disable or remove the non-compliant SWLAN until the site has all required approvals for operation.'
  impact 0.7
  ref 'DPMS Target Harris Secnet 11'
  tag check_id: 'C-22005r1_chk'
  tag severity: 'high'
  tag gid: 'V-18582'
  tag rid: 'SV-20126r1_rule'
  tag stig_id: 'WIR0215'
  tag gtitle: 'SWLAN CCAO Approval'
  tag fix_id: 'F-34118r1_fix'
  tag 'documentable'
end
