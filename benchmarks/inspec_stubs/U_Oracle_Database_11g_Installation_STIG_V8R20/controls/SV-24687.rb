control 'SV-24687' do
  title 'Remote adminstrative connections to the database should be encrypted.'
  desc 'Communications between a client and database service across the network may contain sensitive information including passwords. This is particularly true in the case of administrative activities. Encryption of remote administrative connections to the database ensures confidentiality of configuration, management, and other administrative data.'
  desc 'check', 'Ask the DBA if the DBMS is accessed remotely for administration purposes.

If it is not, this check is Not a Finding.

If it is, ask the DBA if the remote access to DBA accounts is made using remote access to the DBMS host or made directly to the database from a remote database client.

If administration is performed using remote access to the DBMS host, review policy and procedures documented or noted in the System Security Plan, along with evidence that remote administration of the DBMS is performed only via an encrypted connection protocol such as SSH or IPSec.

If it is not, this is a Finding.

If administration is performed from a remote database client, confirm that a dedicated database listener that encrypts communications exists for remote administrative communications.

If a DBMS listener that encrypts traffic is not configured, this is a Finding.

If any listeners on the DBMS host are configured to accept unencrypted traffic, review documented policy, procedures and evidence of training DBAs not to use the unencrypted listener for remote access to DBA accounts.

If no such policy exists or the DBAs have not been instructed not to use the unencrypted connections, this is a Finding.

Note: Out-Of-Band (OOB) is allowed for remote administration, however, OOB alone does not maintain encryption of network traffic from source to destination and is a Finding for this check.

Ensure unclassified, sensitive data transmitted through a commercial or wireless network are encrypted using NIST-certified cryptography.'
  desc 'fix', "Where remote access to DBA accounts is not allowed, develop, document and implement policies and train DBAs that remote access to DBA accounts is prohibited.  

Where remote access to DBA accounts is allowed, the remote connection must be encrypted.

Ensure unclassified, sensitive data transmitted through a commercial or wireless network are encrypted using NIST-certified cryptography.

If remote access is established via the database listener, then install a dedicated listener configured to encrypt all traffic for use by DBAs for remote access.

This requires use of Oracle Advanced Security and Oracle Wallet Manager.

See the Oracle Advanced Security Guide, Configuring Network Data Encryption and Integrity for Oracle Servers and Clients for details.

Configure the listener to require SSL for the DBA connections by specifying the TCPS as the network protocol.

Sample listener.ora entries:

DBALSNR =
  (DESCRIPTION =
    (ADDRESS = (PROTOCOL = TCPS) (HOST = [IP]) (PORT = 1575))
    (CONNECT_DATA = 
      (SERVER = DEDICATED)
      (SERVICE_NAME = [SID])
    )
  )

Configure the server's FIPS.ORA file to use FIPS 140-2 compliant settings to encrypt the traffic and ensure integrity of the transmission.

In the FIPS.ORA file in the $ORACLE_HOME/ldap/admin directory or the directory specified in the FIPS_HOME environment variable for the dedicated listener on the server, add the following line:

  SSLFIPS_140=TRUE

Monitor the listener log files for evidence of any unencrypted remote access to DBA accounts."
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29218r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3825'
  tag rid: 'SV-24687r1_rule'
  tag stig_id: 'DG0093-ORACLE11'
  tag gtitle: 'Remote administrative connection encryption'
  tag fix_id: 'F-22699r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
