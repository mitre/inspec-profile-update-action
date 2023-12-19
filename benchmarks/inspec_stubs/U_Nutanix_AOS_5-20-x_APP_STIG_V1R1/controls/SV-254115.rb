control 'SV-254115' do
  title 'Nutanix AOS must protect the confidentiality and integrity of all information at rest.'
  desc 'When data is written to digital media such as hard drives, mobile computers, external/removable hard drives, personal digital assistants, flash/thumb drives, etc., there is risk of data loss and data compromise.

Fewer protection measures are needed for media containing information determined by the organization to be in the public domain, to be publicly releasable, or to have limited or no adverse impact if accessed by other than authorized personnel. In these situations, it is assumed the physical access controls where the media resides provide adequate protection.

As part of a defense-in-depth strategy, data owners and DoD consider routinely encrypting information at rest on selected secondary storage devices. The employment of cryptography is at the discretion of the information owner/steward. The selection of the cryptographic mechanisms used is based upon maintaining the confidentiality and integrity of the information.

The strength of mechanisms is commensurate with the classification and sensitivity of the information.

The application server must directly provide, or provide access to, cryptographic libraries and functionality that allow applications to encrypt data when it is stored.

'
  desc 'check', 'Confirm Nutanix AOS is set to use data at rest encryption.

1. Log in to Prism Element.
2. Click on the gear icon in the upper right.
3. Navigate to the Data-at-Rest Encryption section.
4. Ensure "Software Encryption" is enabled.

If Software Encryption is not configured, this is a finding.'
  desc 'fix', 'Configure Nutanix AOS to use data at rest encryption

1. Log in to Prism Element.
2. Click on the gear icon in the upper right.
3. Navigate to the Data-at-Rest Encryption section.
4. Select "edit configuration".
5. Select either the Cluster local KMS or an External KMS.
6.  Click "Protect" and then type "ENCRYPT" to confirm.'
  impact 0.7
  ref 'DPMS Target Nutanix AOS 5.20.x Application'
  tag check_id: 'C-57600r846431_chk'
  tag severity: 'high'
  tag gid: 'V-254115'
  tag rid: 'SV-254115r846433_rule'
  tag stig_id: 'NUTX-AP-000450'
  tag gtitle: 'SRG-APP-000231-AS-000133'
  tag fix_id: 'F-57551r846432_fix'
  tag satisfies: ['SRG-APP-000231-AS-000133', 'SRG-APP-000231-AS-000156', 'SRG-APP-000428-AS-000265', 'SRG-APP-000429-AS-000157']
  tag 'documentable'
  tag cci: ['CCI-001199', 'CCI-002475', 'CCI-002476']
  tag nist: ['SC-28', 'SC-28 (1)', 'SC-28 (1)']
end
