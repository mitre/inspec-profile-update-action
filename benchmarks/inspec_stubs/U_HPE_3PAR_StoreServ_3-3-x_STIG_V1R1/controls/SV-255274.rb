control 'SV-255274' do
  title 'The HPE 3PAR OS must be configured to implement cryptographic mechanisms to prevent the unauthorized modification or disclosure of all information at rest on all operating system components.'
  desc 'Operating systems handling data requiring data-at-rest protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields).

The HPE 3PAR OS protects data at rest through the use of Self-Encrypting Drives, and a licensed feature that takes ownership of them. The feature requires an authorized installer to install and activate it.

'
  desc 'check', 'Review the requirements by the Information Owner to discover whether the system stores sensitive or classified information.

If the system does not store sensitive or classified information, this requirement is not applicable.

If the system does store sensitive or classified information, use the following command to display the state of encryption:

cli% controlencryption status

If Licensed, Enabled, or BackupSaved is not "Yes", or Keystore is not "EKM", this is a finding.'
  desc 'fix', 'Contact an authorized service partner to install and configure the encryption license feature.'
  impact 0.5
  ref 'DPMS Target HPE 3PAR StoreServ 3.3.x'
  tag check_id: 'C-58947r870139_chk'
  tag severity: 'medium'
  tag gid: 'V-255274'
  tag rid: 'SV-255274r870141_rule'
  tag stig_id: 'HP3P-33-001200'
  tag gtitle: 'SRG-OS-000404-GPOS-00183'
  tag fix_id: 'F-58891r870140_fix'
  tag satisfies: ['SRG-OS-000404-GPOS-00183', 'SRG-OS-000405-GPOS-00184']
  tag 'documentable'
  tag cci: ['CCI-002475', 'CCI-002476']
  tag nist: ['SC-28 (1)', 'SC-28 (1)']
end
