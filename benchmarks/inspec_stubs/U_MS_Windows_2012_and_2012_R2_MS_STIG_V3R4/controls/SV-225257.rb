control 'SV-225257' do
  title 'Systems requiring data at rest protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.'
  desc 'This requirement addresses protection of user-generated data, as well as operating system-specific configuration data. Organizations may choose to employ different mechanisms to achieve confidentiality and integrity protections, as appropriate, in accordance with the security category and/or classification of the information.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields).'
  desc 'check', 'Verify systems that require additional protections due to factors such as inadequate physical protection or sensitivity of the data employ encryption to protect the confidentiality and integrity of all information at rest.  If it does not, this is a finding.'
  desc 'fix', 'Configure systems that require additional protections due to factors such as inadequate physical protection or sensitivity of the data to employ encryption to protect the confidentiality and integrity of all information at rest.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-26956r471113_chk'
  tag severity: 'medium'
  tag gid: 'V-225257'
  tag rid: 'SV-225257r569185_rule'
  tag stig_id: 'WN12-00-000020'
  tag gtitle: 'SRG-OS-000185-GPOS-00079'
  tag fix_id: 'F-26944r471114_fix'
  tag 'documentable'
  tag legacy: ['SV-72055', 'V-57645']
  tag cci: ['CCI-001199', 'CCI-002475', 'CCI-002476']
  tag nist: ['SC-28', 'SC-28 (1)', 'SC-28 (1)']
end
