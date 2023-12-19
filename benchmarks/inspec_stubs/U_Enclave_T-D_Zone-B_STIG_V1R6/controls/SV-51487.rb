control 'SV-51487' do
  title 'Ports, protocols, and services visible to DoD operational networks or ISPs must follow DoDI 8551.1 policy.'
  desc 'In accordance with the DoD 8551.1 policy, the test and development environment may require external access to live operational data to perform final stage testing.  All network connections for the test and development environment must make use of the PPS CAL at the appropriate boundaries.'
  desc 'check', 'Review the latest version of the PPS CAL for those ports, protocols, and services visible to DoD-managed components.  If the organization is using ports, protocols, or services deemed not acceptable by the PPS CAL or requiring Authorization Official approval without proper documentation, this is a finding.'
  desc 'fix', 'Configure all ports, protocols, and services visible to DoD-managed components as described in the DoDI 8551.1 PPSM policy.'
  impact 0.5
  ref 'DPMS Target Test Enclave - Zone B'
  tag check_id: 'C-46801r2_chk'
  tag severity: 'medium'
  tag gid: 'V-39629'
  tag rid: 'SV-51487r1_rule'
  tag stig_id: 'ENTD0170'
  tag gtitle: 'ENTD0170 - PPS does not following the DoDI 8551.1.'
  tag fix_id: 'F-44640r2_fix'
  tag 'documentable'
  tag ia_controls: 'DCPP-1'
end
