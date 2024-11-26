control 'SV-6780' do
  title 'The manufacturer’s default PKI keys have not been changed prior to attaching the switch to the SAN Fabric.'
  desc "If the manufacturer's default PKI keys are allowed to remain active on the device, it can be accessed by a malicious individual with access to the default key.
The IAO/NSO will ensure that the manufacturer’s default PKI keys are changed prior to attaching the switch to the SAN Fabric."
  desc 'check', 'The reviewer will, with the assistance of the IAO/NSO, verify that the manufacturer’s default PKI keys have been changed prior to attaching the switch to the SAN Fabric.'
  desc 'fix', 'Depending on the functionality allowed by the device, develop a plan remove, disable or change the manufacturer’s default PKI certificate so that it cannot be used for identification and authorization.  Obtain CM approval for the plan and implement the plan.'
  impact 0.3
  ref 'DPMS Target SANS Storage Device'
  ref 'DPMS Target SANS Switch'
  tag check_id: 'C-2548r1_chk'
  tag severity: 'low'
  tag gid: 'V-6638'
  tag rid: 'SV-6780r1_rule'
  tag stig_id: 'SAN04.015.00'
  tag gtitle: 'Default PKI keys'
  tag fix_id: 'F-6237r1_fix'
  tag 'documentable'
  tag potential_impacts: 'The manufacturer may need to access the device for maintenance.  If the PKI keys cannot be reestablished this will fail.'
  tag responsibility: ['Information Assurance Officer', 'Network Security Officer']
  tag ia_controls: 'IAIA-1, IAIA-2'
end
