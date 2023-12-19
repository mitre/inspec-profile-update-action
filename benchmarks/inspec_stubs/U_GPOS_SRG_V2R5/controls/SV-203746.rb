control 'SV-203746' do
  title 'The operating system must implement cryptographic mechanisms to prevent unauthorized disclosure of all information at rest on all operating system components.'
  desc 'Operating systems handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields).'
  desc 'check', 'Verify the operating system implements cryptographic mechanisms to prevent unauthorized disclosure of all information at rest on all operating system components. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to implement cryptographic mechanisms to prevent unauthorized disclosure of all information at rest on all operating system components.'
  impact 0.7
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3871r375302_chk'
  tag severity: 'high'
  tag gid: 'V-203746'
  tag rid: 'SV-203746r877378_rule'
  tag stig_id: 'SRG-OS-000405-GPOS-00184'
  tag gtitle: 'SRG-OS-000405'
  tag fix_id: 'F-3871r375303_fix'
  tag 'documentable'
  tag legacy: ['SV-70999', 'V-56739']
  tag cci: ['CCI-002476']
  tag nist: ['SC-28 (1)']
end
