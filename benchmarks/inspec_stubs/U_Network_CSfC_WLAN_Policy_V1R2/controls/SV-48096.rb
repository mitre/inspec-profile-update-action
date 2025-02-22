control 'SV-48096' do
  title 'A Secure WLAN (SWLAN) connected to the SIPRNet must have a SIPRNet connection approval package on file with the Classified Connection Approval Office (CCAO).'
  desc 'The CCAO approval process provides assurance that the SWLAN use is appropriate and does not introduce unmitigated risks into the SIPRNET.'
  desc 'check', 'Review documentation.  Verify the SWLAN system CCAO approval documentation exists and has been approved and has a SIPRNet Interim Approval to Operate (IATO) or Approval to Operate (ATO) in GIAP database.

If CCAO approval documentation is not available, this is a finding.'
  desc 'fix', 'Disable or remove the non-compliant SWLAN until the site has all required approvals for operation.'
  impact 0.7
  ref 'DPMS Target CSfC Policy - WLAN CP'
  tag check_id: 'C-44835r1_chk'
  tag severity: 'high'
  tag gid: 'V-36594'
  tag rid: 'SV-48096r1_rule'
  tag stig_id: 'WIR-CWLAN-05'
  tag gtitle: 'SWLAN CCAO Approval'
  tag fix_id: 'F-41234r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Information Assurance Manager']
  tag ia_controls: 'ECWN-1'
end
