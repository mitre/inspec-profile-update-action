control 'SV-51294' do
  title 'Application development must not occur on DoD operational network segments.'
  desc 'To reduce the risk of compromise of DoD operational networks and data, application and system development needs to be limited to systems within a network segment designated for development only.'
  desc 'check', "Review the organization's network diagrams to determine whether network segments for development have been established and outlined in the documentation.  If application development occurs on DoD operational networks, this is a finding.  

If there isn't any application development occurring in the zone environment, this requirement is not applicable."
  desc 'fix', 'Designate network segments for applications and systems development.  Document these designated network segments in the network diagrams for the T&D environment.'
  impact 0.5
  ref 'DPMS Target Test Enclave - Zone A'
  tag check_id: 'C-46711r5_chk'
  tag severity: 'medium'
  tag gid: 'V-39436'
  tag rid: 'SV-51294r1_rule'
  tag stig_id: 'ENTD0060'
  tag gtitle: 'ENTD0060 - Development on operational network segments.'
  tag fix_id: 'F-44449r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
