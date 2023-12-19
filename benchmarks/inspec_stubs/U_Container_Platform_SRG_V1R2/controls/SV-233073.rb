control 'SV-233073' do
  title 'The container platform runtime must enforce ports, protocols, and services that adhere to the PPSM CAL.'
  desc 'Ports, protocols, and services within the container platform runtime must be controlled and conform to the PPSM CAL. Those ports, protocols, and services that fall outside the PPSM CAL must be blocked by the runtime. Instructions on the PPSM can be found in DoD Instruction 8551.01 Policy.'
  desc 'check', 'Review the container platform documentation and deployment configuration to determine which ports and protocols are enabled. 

Verify the ports and protocols being used are not prohibited by PPSM CAL in accordance to DoD Instruction 8551.01 Policy and are necessary for the operations and applications.

If any of the ports or protocols is prohibited or not necessary for the operation, this is a finding.'
  desc 'fix', 'Configure the container platform to disable any ports or protocols that are prohibited by the PPSM CAL and not necessary for the operation.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36009r601891_chk'
  tag severity: 'medium'
  tag gid: 'V-233073'
  tag rid: 'SV-233073r601892_rule'
  tag stig_id: 'SRG-APP-000142-CTR-000325'
  tag gtitle: 'SRG-APP-000142'
  tag fix_id: 'F-35977r600707_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
