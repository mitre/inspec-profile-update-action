control 'SV-206614' do
  title 'The DBMS must generate audit records when categories of information (e.g., classification levels/security levels) are accessed.'
  desc 'Changes in categories of information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected.

For detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security Requirements for Federal Information and Information Systems.'
  desc 'check', 'Review DBMS documentation to verify that audit records can be produced when categories of information are accessed, to include reads, creations, modifications, and deletions.

If the DBMS is not capable of this, this is a finding.

Review the DBMS/database security and audit configurations to verify that audit records are produced when categories of information are accessed, to include reads, creations, modifications, and deletions.

If they are not produced, this is a finding.'
  desc 'fix', 'Deploy a DBMS capable of producing the required audit records when categories of information are accessed.

Configure the DBMS to produce audit records when categories of information are accessed, to include reads, creations, modifications, and deletions.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6874r291510_chk'
  tag severity: 'medium'
  tag gid: 'V-206614'
  tag rid: 'SV-206614r617447_rule'
  tag stig_id: 'SRG-APP-000494-DB-000344'
  tag gtitle: 'SRG-APP-000494'
  tag fix_id: 'F-6874r291511_fix'
  tag 'documentable'
  tag legacy: ['SV-72525', 'V-58095']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
