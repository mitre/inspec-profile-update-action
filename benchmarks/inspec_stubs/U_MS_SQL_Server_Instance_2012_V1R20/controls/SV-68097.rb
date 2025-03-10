control 'SV-68097' do
  title 'SQL Server databases in the unclassified environment, containing sensitive information, must be encrypted using approved cryptography.'
  desc "Cryptography is only as strong as the encryption modules/algorithms employed to encrypt the data.

Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data.

Data files that are not encrypted are vulnerable to theft. When data files are not encrypted, they can be copied and opened on a separate system. The data can be compromised without the information owner's knowledge that the theft has even taken place."
  desc 'check', 'If the system exists in the Classified environment, this is NA.

For each database under the SQL Server instance, review the system documentation to determine whether the database holds sensitive information. If it does not, this is not a finding.

If it does handle sensitive information, review the system documentation and configuration to determine whether the sensitive information is protected by NIST-approved cryptography.  If not, this is a finding.'
  desc 'fix', 'Configure SQL Server to encrypt sensitive data stored in each database. Use only NIST-certified cryptography to provide encryption.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-54717r1_chk'
  tag severity: 'medium'
  tag gid: 'V-53877'
  tag rid: 'SV-68097r2_rule'
  tag stig_id: 'SQL2-00-019601'
  tag gtitle: 'SRG-APP-000196-DB-000301'
  tag fix_id: 'F-58707r1_fix'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
