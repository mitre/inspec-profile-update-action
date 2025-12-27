control 'SV-251351' do
  title 'Tunneling of classified traffic across an unclassified IP transport network must employ cryptographic algorithms in accordance with CNSS Policy No. 15.'
  desc 'When transporting classified data over an unclassified IP network, it is imperative that traffic from the classified enclave or community of interest is encrypted prior reaching the point of presence or service delivery node of the unclassified network. Confidentiality and integrity of the classified traffic must be preserved by employing cryptographic algorithms in accordance with CNSS Policy No. 15 which requires the appropriate Suite B cryptographic algorithms listed in ANNEX B or a commensurate suite of NSA-approved cryptographic algorithms.'
  desc 'check', 'Review the configuration of the IPsec VPN gateway and verify that the tunnel provisioned for transporting classified traffic across an unclassified IP transport network is using cryptographic algorithms in accordance with CNSS Policy No. 15.

If cryptographic algorithms used for tunneling classified traffic across an unclassified network are not in accordance with CNSS Policy No. 15, this is a finding.'
  desc 'fix', 'Configure the tunnel used for transporting classified traffic across an unclassified IP transport network to negotiate with the remote end point to employ cryptographic algorithms in accordance with CNSS Policy No. 15.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-54786r806006_chk'
  tag severity: 'medium'
  tag gid: 'V-251351'
  tag rid: 'SV-251351r806008_rule'
  tag stig_id: 'NET-TUNL-031'
  tag gtitle: 'NET-TUNL-031'
  tag fix_id: 'F-54739r806007_fix'
  tag 'documentable'
  tag legacy: ['V-14743', 'SV-15499']
  tag cci: ['CCI-002396', 'CCI-002418']
  tag nist: ['SC-7 (4) (c)', 'SC-8']
end
