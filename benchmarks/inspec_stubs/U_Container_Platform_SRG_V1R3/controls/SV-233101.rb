control 'SV-233101' do
  title 'The container platform must map the authenticated identity to the individual user or group account for PKI-based authentication.'
  desc 'The container platform and its components may require authentication before use. When the authentication is PKI-based, the container platform or component must map the certificate to a user account. If the certificate is not mapped to a user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.'
  desc 'check', 'Review documentation and configuration to ensure the container platform provides a PKI integration capability that meets DoD PKI infrastructure requirements. 

If the container platform is not configured to meet this requirement, this is a finding.'
  desc 'fix', 'Configure the container platform to utilize the DoD Enterprise PKI infrastructure.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36037r600790_chk'
  tag severity: 'medium'
  tag gid: 'V-233101'
  tag rid: 'SV-233101r600792_rule'
  tag stig_id: 'SRG-APP-000177-CTR-000465'
  tag gtitle: 'SRG-APP-000177'
  tag fix_id: 'F-36005r600791_fix'
  tag 'documentable'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
