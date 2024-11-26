control 'SV-213699' do
  title 'If passwords are used for authentication, DB2 must transmit only encrypted representations of passwords.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates.

Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires AO approval.

In such cases, passwords need to be protected at all times, and encryption is the standard method for protecting passwords during transmission.

DBMS passwords sent in clear text format across the network are vulnerable to discovery by unauthorized users. Disclosure of passwords may easily lead to unauthorized access to the database.'
  desc 'check', 'Run the following command to find the value of the authentication parameter: 

$db2 get dbm cfg 

If the AUTHENTICATION parameter is not set to SERVER_ENCRYPT, this is a finding.

Run the following command to find the value of the registry variable DB2AUTH: 

$db2set -all

If the value of DB2AUTH is not set to JCC_ENFORCE_SECMEC, or DB2AUTH is not set (i.e. a row is not returned for DB2AUTH from the above command), this is a finding.'
  desc 'fix', 'Run the following command to set the value of the authentication encryption to SERVER_ENCRYPT: 

$db2 update dbm cfg using authentication server_encrypt

Run the following db2set command to set the value of DB2AUTH to JCC_ENFORCE_SECMEC: 

$db2set DB2AUTH=JCC_ENFORCE_SECMEC

Note: It is recommended to set the ALTERNATE_AUTH_ENC database manager configuration parameter to AES_ONLY to require that AES encryption be used.'
  impact 0.5
  ref 'DPMS Target IBM DB2 V10.5 LUW'
  tag check_id: 'C-14920r295146_chk'
  tag severity: 'medium'
  tag gid: 'V-213699'
  tag rid: 'SV-213699r917664_rule'
  tag stig_id: 'DB2X-00-004100'
  tag gtitle: 'SRG-APP-000172-DB-000075'
  tag fix_id: 'F-14918r917663_fix'
  tag 'documentable'
  tag legacy: ['SV-89161', 'V-74487']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
