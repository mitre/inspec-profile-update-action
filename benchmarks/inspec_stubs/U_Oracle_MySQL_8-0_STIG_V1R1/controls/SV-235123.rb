control 'SV-235123' do
  title 'The MySQL Database Server 8.0 must generate audit records when categories of information (e.g., classification levels/security levels) are deleted.'
  desc 'Changes in categories of information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected.

For detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security Requirements for Federal Information and Information Systems.'
  desc 'check', 'Review DBMS documentation to verify that audit records can be produced when categories of information are deleted.

If the DBMS is not capable of this, this is a finding.

Review the DBMS/database security and audit configurations to verify that audit records are produced when categories of information are deleted.

If they are not produced, this is a finding.'
  desc 'fix', 'Deploy a MySQL Database Server 8.0 capable of producing the required audit records when categories of information are deleted.

Configure the MySQL Database Server 8.0 to produce audit records when categories of information are deleted.'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38342r623489_chk'
  tag severity: 'medium'
  tag gid: 'V-235123'
  tag rid: 'SV-235123r638812_rule'
  tag stig_id: 'MYS8-00-003600'
  tag gtitle: 'SRG-APP-000502-DB-000348'
  tag fix_id: 'F-38305r623490_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
