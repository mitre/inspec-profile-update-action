control 'SRG-NET-000352-VVEP-00038_rule' do
  title 'The Unified Communications Endpoint must be configured to use cryptographic algorithms approved by NSA to protect NSS when transporting classified traffic across an unclassified network.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data.

NIST cryptographic algorithms are approved by NSA to protect NSS. Based on an analysis of the impact of quantum computing, cryptographic algorithms specified by CNSSP-15 and approved for use in products in the CSfC program have been changed to more stringent protocols and configured with increased bit sizes and other secure characteristics to protect against quantum computing threats. The Commercial National Security Algorithm Suite (CNSA Suite) replaces Suite B.'
  desc 'check', 'Verify the Unified Communications Endpoint processing classified information over public networks implements NSA-approved cryptography. 

If the Unified Communications Endpoint processing classified information over public networks does not implement NSA-approved cryptography, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Endpoint processing classified information over public networks to implement NSA-approved cryptography.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000352-VVEP-00038_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000352-VVEP-00038'
  tag rid: 'SRG-NET-000352-VVEP-00038_rule'
  tag stig_id: 'SRG-NET-000352-VVEP-00038'
  tag gtitle: 'SRG-NET-000352-VVEP-00038'
  tag fix_id: 'F-SRG-NET-000352-VVEP-00038_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
