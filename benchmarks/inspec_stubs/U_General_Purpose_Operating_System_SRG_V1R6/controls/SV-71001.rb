control 'SV-71001' do
  title 'The operating system must implement cryptographic mechanisms to prevent unauthorized modification of all information at rest on all operating system components.'
  desc 'Operating systems handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields).'
  desc 'check', 'Verify the operating system implements cryptographic mechanisms to prevent unauthorized modification of all information at rest on all operating system components. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to implement cryptographic mechanisms to prevent unauthorized modification of all information at rest on all operating system components.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57311r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56741'
  tag rid: 'SV-71001r1_rule'
  tag stig_id: 'SRG-OS-000404-GPOS-00183'
  tag gtitle: 'SRG-OS-000404-GPOS-00183'
  tag fix_id: 'F-61637r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002475']
  tag nist: ['SC-28 (1)']
end
