control 'SV-6769' do
  title 'Network management ports on the SAN fabric switches except those needed to support the operational commitments of the sites are not disabled.'
  desc 'Enabled network management ports that are not required expose the SAN fabric switch and the entire network to unnecessary vulnerabilities.  By disabling these unneeded ports the exposure profile of the device and network is diminished.
The IAO/NSO will disable all network management ports on the SAN fabric switches except those needed to support the operational commitments of the sites.'
  desc 'check', 'The reviewer will, with the assistance of the IAO/NSO, verify that all network management ports on the SAN fabric switches are disabled except those needed to support the operational commitments of the sites.'
  desc 'fix', 'Develop a plan to locate and disable all network management ports that are not required to support the operational commitments of the sites.  Obtain CM approval of the plan and then execute the plan.'
  impact 0.5
  ref 'DPMS Target SANS Switch'
  tag check_id: 'C-2529r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6635'
  tag rid: 'SV-6769r1_rule'
  tag stig_id: 'SAN04.012.00'
  tag gtitle: 'SAN Network Management Ports Fabric Switch'
  tag fix_id: 'F-6230r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Switch Administrator']
  tag ia_controls: 'DCBP-1'
end
