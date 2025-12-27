control 'SV-85113' do
  title 'The storage system must implement cryptographic mechanisms to prevent unauthorized modification or disclosure of all information at rest on all storage system components.'
  desc 'Operating systems handling data requiring “data at rest” protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields).

'
  desc 'check', 'Review the requirements by the Information Owner to discover whether the system stores sensitive or classified information.

If the system does not store sensitive or classified information, this is not applicable.

Verify that data at rest encryption is enabled by entering the following command:

cli% controlencryption status
Licensed | Enabled | BackupSaved | State | SeqNum | Keystore
yes | Yes | no | normal | 0 | ---

If the "Enabled" flag is not set to "Yes" as shown in the output above, this is a finding.'
  desc 'fix', 'Contact an authorized installer to enable the data-at-rest encryption feature. The data at rest encryption feature has hardware and licensing pre-requisites which must be verified by an authorized installer prior to enabling the feature.'
  impact 0.3
  ref 'DPMS Target HPE 3PAR OS 3.2.2'
  tag check_id: 'C-70891r1_chk'
  tag severity: 'low'
  tag gid: 'V-70491'
  tag rid: 'SV-85113r1_rule'
  tag stig_id: 'HP3P-32-001200'
  tag gtitle: 'SRG-OS-000404-GPOS-00183'
  tag fix_id: 'F-76729r1_fix'
  tag satisfies: ['SRG-OS-000404-GPOS-00183', 'SRG-OS-000405-GPOS-00184']
  tag 'documentable'
  tag cci: ['CCI-002475', 'CCI-002476']
  tag nist: ['SC-28 (1)', 'SC-28 (1)']
end
