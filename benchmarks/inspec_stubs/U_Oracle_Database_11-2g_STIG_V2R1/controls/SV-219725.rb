control 'SV-219725' do
  title 'Use of the DBMS installation account must be logged.'
  desc 'The DBMS installation account may be used by any authorized user to perform DBMS installation or maintenance. Without logging, accountability for actions attributed to the account is lost.'
  desc 'check', 'Review documented and implemented procedures for monitoring the use of the DBMS software installation account in the System Security Plan.

If use of this account is not monitored or procedures for monitoring its use do not exist or are incomplete, this is a Finding.
 
NOTE: On Windows systems, The Oracle DBMS software is installed using an account with administrator privileges. Ownership should be reassigned to a dedicated OS account used to operate the DBMS software. If monitoring does not include all accounts with administrator privileges on the DBMS host, this is a Finding.'
  desc 'fix', 'Develop, document and implement a logging procedure for use of the DBMS software installation account that provides accountability to individuals for any actions taken by the account.

Host system audit logs should be included in the DBMS account usage log along with an indication of the person who accessed the account and an explanation for the access.

Ensure all accounts with administrator privileges are monitored for DBMS host on Windows OS platforms.'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-21450r307024_chk'
  tag severity: 'medium'
  tag gid: 'V-219725'
  tag rid: 'SV-219725r401224_rule'
  tag stig_id: 'O112-BP-024200'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21449r307025_fix'
  tag 'documentable'
  tag legacy: ['SV-68261', 'V-54021']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
