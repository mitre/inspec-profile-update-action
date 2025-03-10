control 'SV-95515' do
  title 'The SDN controller must be configured to generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.'
  desc 'Providing too much information in error messages on the screen or printout risks compromising the data and security of the SDN controller. The structure and content of error messages need to be carefully considered by the organization. The extent to which information systems are able to identify and handle error conditions is guided by organizational policy and operational requirements.'
  desc 'check', 'Review the SDN controller configuration to determine that error messages do not contain information beyond what is needed for troubleshooting controller and network problems. 

If the controller is not configured to generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries, this is a finding.'
  desc 'fix', 'Configure the SDN controller to generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.'
  impact 0.5
  ref 'DPMS Target SRG-NET-SDC'
  tag check_id: 'C-80541r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80805'
  tag rid: 'SV-95515r1_rule'
  tag stig_id: 'SRG-NET-000512-SDN-001080'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-87659r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
