control 'SV-6730' do
  title 'The SANs are not compliant with overall network security architecture, appropriate enclave, and data center security requirements in the Network Infrastructure STIG and the Enclave STIG'
  desc 'Inconsistencies with the Network Infrastructure STIG, the Enclave STIG, and the SAN implementation can lead to the creation of vulnerabilities in the network or the enclave.'
  desc 'check', 'The reviewer will interview the IAO/NSO to validate that SANs are compliant with overall network security architecture, appropriate enclave, and data center security requirements in the Network Infrastructure STIG and the Enclave STIG.  

NOTE: The intent of this check is to ensure that the other checklists were applied. If they are applied then, regardless of what the findings are, this is not a finding. The objective of this policy is met if the other checklists were applied and documented.'
  desc 'fix', 'Perform a self assessment with the Network Infrastructure checklist and the Enclave checklist or schedule a formal review with FSO.'
  impact 0.5
  ref 'DPMS Target SANS Storage Device'
  ref 'DPMS Target SANS Switch'
  tag check_id: 'C-2444r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6610'
  tag rid: 'SV-6730r1_rule'
  tag stig_id: 'SAN04.002.00'
  tag gtitle: 'Compliance with Network Infrastructure and Enclave'
  tag fix_id: 'F-6199r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Network Security Officer']
end
