control 'SV-206555' do
  title 'If DBMS authentication, using passwords, is employed, the DBMS must enforce the DoD standards for password complexity and lifetime.'
  desc 'OS/enterprise authentication and identification must be used (SRG-APP-000023-DB-000001).  Native DBMS authentication may be used only when circumstances make it unavoidable; and must be documented and AO-approved.

The DoD standard for authentication is DoD-approved PKI certificates.  Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires AO approval.

In such cases, the DoD standards for password complexity and lifetime must be implemented.  DBMS products that can inherit the rules for these from the operating system or access control program (e.g., Microsoft Active Directory) must be configured to do so.  For other DBMSs, the rules must be enforced using available configuration parameters or custom code.'
  desc 'check', "If DBMS authentication, using passwords, is not employed, this is not a finding.

If the DBMS is configured to inherit password complexity and lifetime rules from the operating system or access control program, this is not a finding.

Review the DBMS settings relating to password complexity. Determine whether the following rules are enforced. If any are not, this is a finding.
a. minimum of 15 characters, including at least one of each of the following character sets:
- Upper-case
- Lower-case
- Numerics
- Special characters (e.g., ~ ! @ # $ % ^ & * ( ) _ + = - ' [ ] / ? > <)
b. Minimum number of characters changed from previous password: 50 percent of the minimum password length; that is, eight

Review the DBMS settings relating to password lifetime. Determine whether the following rules are enforced. If any are not, this is a finding.
a. Password lifetime limits for interactive accounts: Minimum 24 hours, maximum 60 days
b. Password lifetime limits for non-interactive accounts: Minimum 24 hours, maximum 365 days
c. Number of password changes before an old one may be reused: Minimum of five"
  desc 'fix', "If the use of passwords is not needed, configure the DBMS to prevent their use if it is capable of this; if it is not so capable, institute policies and procedures to prohibit their use.

If the DBMS can inherit password complexity rules from the operating system or access control program, configure it to do so.

Otherwise, use DBMS configuration parameters and/or custom code to enforce the following rules for passwords:

a. minimum of 15 characters, including at least one of each of the following character sets:
- Upper-case
- Lower-case
- Numerics
- Special characters (e.g., ~ ! @ # $ % ^ & * ( ) _ + = - ' [ ] / ? > <)
b. Minimum number of characters changed from previous password: 50 percent of the minimum password length; that is, eight
c. Password lifetime limits for interactive accounts: Minimum 24 hours, maximum 60 days
d. Password lifetime limits for non-interactive accounts: Minimum 24 hours, maximum 365 days
e. Number of password changes before an old one may be reused: Minimum of five"
  impact 0.7
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6815r291333_chk'
  tag severity: 'high'
  tag gid: 'V-206555'
  tag rid: 'SV-206555r810835_rule'
  tag stig_id: 'SRG-APP-000164-DB-000401'
  tag gtitle: 'SRG-APP-000164'
  tag fix_id: 'F-6815r291334_fix'
  tag 'documentable'
  tag legacy: ['SV-75897', 'V-61407']
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
