control 'SV-6739' do
  title 'Prior to installing SAN components (servers, switches, and management stations) onto the DOD network infrastructure, components are not configured to meet the applicable STIG requirements.'
  desc 'Many SAN components (servers, switches, management stations) have security requirements from other STIGs.  It will be verified that all requirement are complied with.
The IAO/NSO will ensure that prior to installing SAN components (servers, switches, and management stations) onto the DOD network infrastructure, components are configured to meet the applicable STIG requirements.'
  desc 'check', 'The reviewer will interview the IAO/NSO and view VMS to verify that prior to installing SAN components (servers, switches, and management stations) onto the DOD network infrastructure, components are configured to meet the applicable STIG requirements.'
  desc 'fix', 'Perform a self assessment using the applicable checklists or scripts on any component device that has not been reviewed or request a formal review from FSO.'
  impact 0.5
  ref 'DPMS Target SANS Storage Device'
  ref 'DPMS Target SANS Switch'
  tag check_id: 'C-2463r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6619'
  tag rid: 'SV-6739r1_rule'
  tag stig_id: 'SAN04.004.00'
  tag gtitle: 'Component Compliance with applicable STIG'
  tag fix_id: 'F-6207r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Network Security Officer']
end
