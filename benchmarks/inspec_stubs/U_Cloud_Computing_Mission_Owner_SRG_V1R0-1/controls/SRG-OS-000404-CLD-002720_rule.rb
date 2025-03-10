control 'SRG-OS-000404-CLD-002720_rule' do
  title 'For storage service offerings, the Mission Owner must configure or ensure the cloud instance uses encryption to protect all DOD files housed in the cloud instance.

Add a requirement for KMS specifically.'
  desc 'Mission systems at all impact levels must have the capability for DOD data to be encrypted at rest with exclusive DOD control of encryption keys and key management. Some CSOs may facilitate this by providing a Hardware Security Module (HSM) or offering customer dedicated HSM devices as a service. CSOs that do not provide such a capability may require Mission Owners to use encryption hardware/software on the DISN or a cloud encryption service that provides DOD control of keys and key management. Some CSOs may offer a KMS service that can suffice for management of customer keys by the customer while preventing CSP access to the keys. An NSA validated CSP KMS is required.

Data-at-rest (DAR) encryption with customer controlled keys and key management protects the DOD data stored in CSOs with the following benefits:
- Maintains the integrity of publicly released information and websites at Level 2 where confidentiality is not an issue.
- Maintains the confidentiality and integrity of CUI at levels 4 and 5 with the following benefits:
- Limits the insider threat vector of unauthorized access by CSP personnel through increasing the work necessary to compromise/access unencrypted DOD data.

 Mission Owners and their AOs should consider the benefits of DAR encryption as well as a cryptography-based process for data destruction and/or spill remediation at Impact Level 2 in addition to the benefit of maintaining integrity of the information.'
  desc 'check', 'Unless encryption and KMS is required by the information owner, for Impact Level 2 public cloud with non-privileged user access to publicly releasable information, this is not applicable.

Verify the cloud storage service is configured to use encryption and KMS to protect all DOD files housed in the virtual storage service. 

If the cloud storage service is not configured to use encryption to protect all DOD files housed in the virtual storage service, this is a finding.'
  desc 'fix', 'This applies to Impact Levels 4/5/6. Applies to Impact Level 2 where Mission Owner has control of the environment.
FedRAMP Moderate, High.

Configure the cloud instance to use encryption to protect all DOD files housed in the virtual storage service.'
  impact 0.7
  tag check_id: 'C-SRG-OS-000404-CLD-002720_chk'
  tag severity: 'high'
  tag gid: 'SRG-OS-000404-CLD-002720'
  tag rid: 'SRG-OS-000404-CLD-002720_rule'
  tag stig_id: 'SRG-OS-000404-CLD-002720'
  tag gtitle: 'SRG-OS-000404-CLD-002720'
  tag fix_id: 'F-SRG-OS-000404-CLD-002720_fix'
  tag 'documentable'
  tag cci: ['CCI-002475']
  tag nist: ['SC-28 (1)']
end
