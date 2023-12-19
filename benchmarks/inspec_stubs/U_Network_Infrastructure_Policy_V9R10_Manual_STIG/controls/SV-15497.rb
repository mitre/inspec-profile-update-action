control 'SV-15497' do
  title 'Enabling a connection that extends DISN IP network connectivity (e.g., NIPRNet and SIPRNet) to any DoD Vendor, Foreign, or Federal Mission Partner enclave or network without a signed DoD CIO approved sponsorship memo is prohibited. For classified connectivity it must be to a DSS approved contractor facility or DoD Component approved foreign government facility.'
  desc 'Having a circuit provisioned that connects the SIPRNet enclave to a non-DoD, foreign, or contractor network puts the enclave and the entire SIPRNet at risk. If the termination point is not operated by the government, there is no control to ensure that the network element at the remote facility is not compromised or connected to another network.'
  desc 'check', 'Review the topology diagram of the classified network.

If there are any leased circuits connecting to DoD Vendor, Foreign, or Federal Mission Partner enclave or network without a signed DoD CIO-approved sponsorship memo, this is a finding.

If classified connectivity is not to a DSS-approved contractor facility or DoD Component-approved foreign government facility, this is a finding.'
  desc 'fix', 'Terminate all leased circuits connecting to DoD Vendor, Foreign, or Federal Mission Partner enclave or network without a signed DoD CIO-approved sponsorship memo.

Terminate all leased circuits for a classified network that is not connecting to a DSS-approved contractor facility or DoD Component-approved foreign government facility.'
  impact 0.7
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-12963r3_chk'
  tag severity: 'high'
  tag gid: 'V-14741'
  tag rid: 'SV-15497r2_rule'
  tag stig_id: 'NET1826'
  tag gtitle: 'Classified circuit terminates in non-DoD facility'
  tag fix_id: 'F-14207r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
