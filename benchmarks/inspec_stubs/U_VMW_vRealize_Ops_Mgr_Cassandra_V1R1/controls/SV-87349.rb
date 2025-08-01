control 'SV-87349' do
  title 'The Cassandra Server must generate audit records when categories of information (e.g., classification levels/security levels) are deleted.'
  desc 'Changes in categories of information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected.

For detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security Requirements for Federal Information and Information Systems.'
  desc 'check', %q(Review the Cassandra Server configuration to ensure audit records are generated when categories of information (e.g., classification levels/security levels) are deleted.

At the command prompt, execute the following command:

# grep '<root' /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml

If level is not set to "ALL", this is a finding.)
  desc 'fix', %q(Configure the Cassandra Server to generate audit records when categories of information (e.g., classification levels/security levels) are deleted.

At the command line execute the following command:

# sed -i 's/^\(\s*\\)<root level=".*">\(\s*\\)$/\1<root level="ALL">\2/' /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml)
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72873r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72717'
  tag rid: 'SV-87349r1_rule'
  tag stig_id: 'VROM-CS-000345'
  tag gtitle: 'SRG-APP-000502-DB-000348'
  tag fix_id: 'F-79121r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
