control 'SV-24844' do
  title 'Remote administration of the DBMS should be restricted to known, dedicated and encrypted network addresses and ports.'
  desc 'Remote administration provides many conveniences that can assist in the maintenance of the designed security posture of the DBMS. On the other hand, remote administration of the database also provides malicious users the ability to access from the network a highly privileged function. Remote administration needs to be carefully considered and used only when sufficient protections against its abuse can be applied. Encryption and dedication of ports to access remote administration functions can help prevent unauthorized access to it.'
  desc 'check', 'Ask the DBA if the DBMS is accessed remotely for administration purposes. If it is not, this check is Not a Finding.

Check DG0093 specifies remote administration encryption for confidentiality.

This check should confirm the use of dedicated and encrypted network addresses and ports.

Review configured network access interfaces for remote DBMS administration.

These may be host-based encryptions such as IPSec or may be configured for the DBMS as part of the network communications and/or in the DBMS listening process.

For DBMS listeners, verify that encrypted ports exist and are restricted to specific network addresses to access the DBMS.

View the System Security Plan to review the authorized procedures and access for remote administration.

If the configuration does not match the specifications in the System Security Plan, this is a Finding.

Note: Out-Of-Band (OOB) is allowed for remote administration, however, OOB alone does not maintain encryption of network traffic from source to destination and is a Finding for this check.'
  desc 'fix', 'Disable remote administration where it is not required.

Consider restricting administrative access to local connections only.

Where necessary, configure the DBMS network communications to provide an encrypted, dedicated port for remote administration access.

Develop and provide procedures for remote administrative access to DBAs that have been authorized for remote administration.

Verify during audit reviews that DBAs do not access the database remotely except through the dedicated and encrypted port.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29405r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15662'
  tag rid: 'SV-24844r1_rule'
  tag stig_id: 'DG0198-ORACLE11'
  tag gtitle: 'DBMS remote administration encryption'
  tag fix_id: 'F-26430r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
