control 'SV-206615' do
  title 'The DBMS must generate audit records when unsuccessful attempts to access categories of information (e.g., classification levels/security levels) occur.'
  desc 'Changes in categories of information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.

For detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security Requirements for Federal Information and Information Systems.'
  desc 'check', 'Review DBMS documentation to verify that audit records can be produced when the system denies or fails to complete attempts to access categories of information, such access to include reads, creations, modifications and deletions.

If the DBMS is not capable of this, this is a finding.

Review the DBMS/database security and audit configurations to verify that audit records are produced when the system denies attempts to access categories of information, such access to include reads, creations, modifications and deletions.

If they are not produced, this is a finding.

Review the DBMS/database security and audit configurations to verify that audit records are produced when other errors prevent attempts to access categories of information, such access to include reads, creations, modifications and deletions.

If they are not produced, this is a finding.'
  desc 'fix', 'Deploy a DBMS capable of producing the required audit records when it denies or fails to complete access to categories of information.

Configure the DBMS to produce audit records when it denies access to categories of information, such access to include reads, creations, modifications and deletions.

Configure the DBMS to produce audit records when other errors prevent access to categories of information, such access to include reads, creations, modifications and deletions.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6875r291513_chk'
  tag severity: 'medium'
  tag gid: 'V-206615'
  tag rid: 'SV-206615r617447_rule'
  tag stig_id: 'SRG-APP-000494-DB-000345'
  tag gtitle: 'SRG-APP-000494'
  tag fix_id: 'F-6875r291514_fix'
  tag 'documentable'
  tag legacy: ['SV-72527', 'V-58097']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
