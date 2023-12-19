control 'SV-219853' do
  title 'Use of the DBMS installation account must be logged.'
  desc 'The DBMS installation account may be used by any authorized user to perform DBMS installation or maintenance. Without logging, accountability for actions attributed to the account is lost.'
  desc 'check', 'Review documented and implemented procedures for monitoring the use of the DBMS software installation account in the System Security Plan.

If use of this account is not monitored or procedures for monitoring its use do not exist or are incomplete, this is a finding.

Note: On Windows systems, The Oracle DBMS software is installed using an account with administrator privileges. Ownership should be reassigned to a dedicated OS account used to operate the DBMS software. If monitoring does not include all accounts with administrator privileges on the DBMS host, this is a finding.'
  desc 'fix', 'Develop, document and implement a logging procedure for use of the DBMS software installation account that provides accountability to individuals for any actions taken by the account.

Host system audit logs should be included in the DBMS account usage log along with an indication of the person who accessed the account and an explanation for the access.

Ensure all accounts with administrator privileges are monitored for DBMS host on Windows OS platforms.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21564r533090_chk'
  tag severity: 'medium'
  tag gid: 'V-219853'
  tag rid: 'SV-219853r879887_rule'
  tag stig_id: 'O121-BP-024200'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21563r533091_fix'
  tag 'documentable'
  tag legacy: ['SV-75979', 'V-61489']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
