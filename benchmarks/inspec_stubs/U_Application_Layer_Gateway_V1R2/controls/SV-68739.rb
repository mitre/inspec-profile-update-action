control 'SV-68739' do
  title 'The ALG that is part of a CDS must enforce organization-defined one-way information flows using hardware mechanisms.'
  desc 'Information flow control regulates where information is allowed to travel within a network and between interconnected networks. The flow of all network traffic must be monitored and controlled so it does not introduce any unacceptable risk to the network infrastructure or data.

For cross domain solutions, use of hardware enforced flow direction is preferable in high risk environments but is not mandatory. Do not enable any connections between security domains beyond the specified one-way flow.

Organization-defined one-way information flows using hardware mechanisms used as part of a CDS system depends on the environment, data, and security boundaries. Organizations implementing CDS must follow the DoD-required process of testing, baselining, and risk assessment to ensure the rigor and accuracy necessary to rely upon a CDS for cross domain security.'
  desc 'check', 'If the ALG is not part of a CDS, this is not applicable.

Verify the ALG is configured to enforce organization-defined one-way information flows using hardware mechanisms.

If the ALG is not configured to enforce organization-defined one-way information flows using hardware mechanisms, this is a finding.'
  desc 'fix', 'If the ALG is part of a CDS, configure the ALG to enforce organization-defined one-way information flows using hardware mechanisms.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55109r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54493'
  tag rid: 'SV-68739r1_rule'
  tag stig_id: 'SRG-NET-000032-ALG-000082'
  tag gtitle: 'SRG-NET-000032-ALG-000082'
  tag fix_id: 'F-59347r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000031', 'CCI-000366']
  tag nist: ['AC-4 (7)', 'CM-6 b']
end
