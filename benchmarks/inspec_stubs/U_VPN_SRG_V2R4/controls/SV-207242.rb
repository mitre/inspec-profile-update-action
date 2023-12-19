control 'SV-207242' do
  title 'The VPN Gateway must use an approved Commercial Solution for Classified (CSfC) when transporting classified traffic across an unclassified network.'
  desc "Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data.

The National Security Agency/Central Security Service's (NSA/CSS) CSfC Program enables commercial products to be used in layered solutions to protect classified National Security Systems (NSS) data. Currently, Suite B cryptographic algorithms are specified by NIST and are used by NSA's Information Assurance Directorate in solutions approved for protecting classified and unclassified NSS. However, quantum resistant algorithms will be required for future required Suite B implementations."
  desc 'check', 'Verify the VPN Gateway uses an approved Commercial Solution for Classified (CSfC) when transporting classified traffic across an unclassified network.

If the VPN Gateway does not use an approved Commercial Solution for Classified (CSfC) when transporting classified traffic across an unclassified network, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to use an approved Commercial Solution for Classified (CSfC) when transporting classified traffic across an unclassified network.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7502r378347_chk'
  tag severity: 'medium'
  tag gid: 'V-207242'
  tag rid: 'SV-207242r608988_rule'
  tag stig_id: 'SRG-NET-000352-VPN-001460'
  tag gtitle: 'SRG-NET-000352'
  tag fix_id: 'F-7502r378348_fix'
  tag 'documentable'
  tag legacy: ['SV-106317', 'V-97179']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
