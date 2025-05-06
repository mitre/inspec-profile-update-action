control 'SV-204770' do
  title 'The application server must protect the confidentiality and integrity of all information at rest.'
  desc 'When data is written to digital media such as hard drives, mobile computers, external/removable hard drives, personal digital assistants, flash/thumb drives, etc., there is risk of data loss and data compromise.

Fewer protection measures are needed for media containing information determined by the organization to be in the public domain, to be publicly releasable, or to have limited or no adverse impact if accessed by other than authorized personnel. In these situations, it is assumed the physical access controls where the media resides provide adequate protection.

As part of a defense-in-depth strategy, data owners and DoD consider routinely encrypting information at rest on selected secondary storage devices. The employment of cryptography is at the discretion of the information owner/steward. The selection of the cryptographic mechanisms used is based upon maintaining the confidentiality and integrity of the information.

The strength of mechanisms is commensurate with the classification and sensitivity of the information.

The application server must directly provide, or provide access to, cryptographic libraries and functionality that allow applications to encrypt data when it is stored.'
  desc 'check', 'Review the application server documentation and configuration to ensure the application server is protecting the confidentiality and integrity of all information at rest.

If the confidentiality and integrity of all information at rest is not protected, this is a finding.'
  desc 'fix', 'Configure the application server to protect the confidentiality and integrity of all information at rest.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4890r282957_chk'
  tag severity: 'medium'
  tag gid: 'V-204770'
  tag rid: 'SV-204770r508029_rule'
  tag stig_id: 'SRG-APP-000231-AS-000133'
  tag gtitle: 'SRG-APP-000231'
  tag fix_id: 'F-4890r282958_fix'
  tag 'documentable'
  tag legacy: ['V-57555', 'SV-71831']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
