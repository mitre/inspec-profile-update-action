control 'SV-222588' do
  title 'The application must implement approved cryptographic mechanisms to prevent unauthorized modification of organization-defined information at rest on organization-defined information system components.'
  desc 'Applications handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields).'
  desc 'check', 'Review the documentation and interview the application administrator.

Identify the data processed by the application and the accompanying data protection requirements.

Determine if the data owner has specified data protection encryption requirements regarding modification of data.

Determine if the application is processing publicly releasable, FOUO or classified data.

Determine if the application configuration information contains sensitive information.

If the data is strictly publicly releasable information and system documentation specifies no data encryption is required for any hosted application data, this is not applicable.

Access the data repository and have the application administrator identify the encryption protections that are utilized.

If the application processes classified data or if the data owner has specified encryption requirements and the application administrator is unable to demonstrate how the data is encrypted, this is a finding.'
  desc 'fix', 'Identify data elements that require protection.

Document the data types and specify encryption requirements.

Encrypt data according to DoD policy or data owner requirements.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24258r493672_chk'
  tag severity: 'medium'
  tag gid: 'V-222588'
  tag rid: 'SV-222588r879799_rule'
  tag stig_id: 'APSC-DV-002340'
  tag gtitle: 'SRG-APP-000428'
  tag fix_id: 'F-24247r493673_fix'
  tag 'documentable'
  tag legacy: ['SV-84849', 'V-70227']
  tag cci: ['CCI-002475']
  tag nist: ['SC-28 (1)']
end
