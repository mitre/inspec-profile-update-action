control 'SV-87291' do
  title 'The Cassandra database must enforce the DoD standards for password complexity and lifetime.'
  desc 'Native DBMS authentication may be used only when circumstances make it unavoidable. In such cases, the DoD standards for password complexity and lifetime must be implemented.  The rules must be enforced using available configuration parameters or custom code.'
  desc 'check', "Review the Cassandra database configuration to ensure the DoD standards for password complexity and lifetime are enforced.

Review the DBMS settings relating to password complexity. Determine whether the following rules are enforced. If any are not, this is a finding.

a. minimum of 15 characters, including at least one of each of the following character sets:
- Upper-case
- Lower-case
- Numeric
- Special characters (e.g., ~ ! @ # $ % ^ & * ( ) _ + = - ' [ ] / ? > <)
b. Minimum number of characters changed from previous password: 50 percent of the minimum password length; that is, eight

Review the DBMS settings relating to password lifetime. Determine whether the following rules are enforced. If any are not, this is a finding.

c. Password lifetime limits: Minimum 24 hours, maximum 60 days
d. Number of password changes before an old one may be reused: Minimum of five"
  desc 'fix', "Configure the Cassandra database to enforce the DoD standards for password complexity and lifetime.

Use configuration parameters and/or custom code to enforce the following rules for passwords:

a. minimum of 15 characters, including at least one of each of the following character sets:
- Upper-case
- Lower-case
- Numeric
- Special characters (e.g., ~ ! @ # $ % ^ & * ( ) _ + = - ' [ ] / ? > <)
b. Minimum number of characters changed from previous password: 50 percent of the minimum password length; that is, eight
c. Password lifetime limits: Minimum 24 hours, maximum 60 days
d. Number of password changes before an old one may be reused: Minimum of five"
  impact 0.7
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72815r1_chk'
  tag severity: 'high'
  tag gid: 'V-72659'
  tag rid: 'SV-87291r1_rule'
  tag stig_id: 'VROM-CS-000135'
  tag gtitle: 'SRG-APP-000164-DB-000401'
  tag fix_id: 'F-79063r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
