control 'SV-222589' do
  title 'The application must use appropriate cryptography in order to protect stored DoD information when required by the information owner or DoD policy.'
  desc 'Applications handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.

Selection of a cryptographic mechanism is based on the need to protect the confidentiality of organizational information. The strength of mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields).

Special care must be taken to cryptographically protect classified data.'
  desc 'check', 'Review the application documentation and interview the application administrator.

Identify the data processed by the application and the accompanying data protection requirements.

Determine if the application is processing publicly releasable, SBU, FOUO, or classified data.

If the data is strictly publicly releasable information with no SBU, FOUO, or classified and system documentation specifies no data encryption is required for any hosted application data, this requirement is not applicable.

Have the application administrator identify the encryption protections that are utilized.

Validate the application is using encryption protections that are commensurate with the data being protected.

If the application is processing classified data, type 1, suite B cryptography, or hardware-based encryption solutions; meeting NSA encryption requirements for classified data processing and storage is required.

If the application processes classified data or if the data owner has specified encryption requirements and the application administrator is unable to demonstrate the type of encryption used or if the application processes classified and does not use type 1, suite B, or NSA-approved hardware-based encryption, this is a finding.'
  desc 'fix', 'Identify data elements that require protection.

Document the data types and specify encryption requirements.

Encrypt classified data using Type 1, Suite B, or other NSA-approved encryption solutions.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24259r493675_chk'
  tag severity: 'medium'
  tag gid: 'V-222589'
  tag rid: 'SV-222589r849482_rule'
  tag stig_id: 'APSC-DV-002350'
  tag gtitle: 'SRG-APP-000429'
  tag fix_id: 'F-24248r493676_fix'
  tag 'documentable'
  tag legacy: ['SV-84851', 'V-70229']
  tag cci: ['CCI-002476']
  tag nist: ['SC-28 (1)']
end
