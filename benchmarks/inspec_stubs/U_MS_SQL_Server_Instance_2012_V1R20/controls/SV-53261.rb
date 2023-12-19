control 'SV-53261' do
  title 'SQL Server must employ cryptographic mechanisms preventing the unauthorized disclosure of information during transmission.'
  desc 'Preventing the disclosure of transmitted information requires that applications take measures to employ some form of cryptographic mechanism in order to protect the information during transmission. This is usually achieved through the use of Transport Layer Security (TLS), VPN, or IPSEC tunnel. 

Information in transmission is particularly vulnerable to attack. If the DBMS does not employ cryptographic mechanisms preventing unauthorized disclosure of information during transit, the information may be compromised.'
  desc 'check', 'If the DBMS exists in the unclassified environment, and data transmission does not cross the boundary between the NIPRNet and the wider Internet, and the application owner and authorizing official have determined that encryption is not required, this is not a finding.

Check SQL Server and network settings to determine whether cryptographic mechanisms are used to prevent the unauthorized disclosure of information during transmission. If not, this is a finding.

Review system documentation to determine whether the system handles classified information. If the system does not handle classified information, the severity of this check should be downgraded to Category II.

From Command Prompt, open SQL Server Configuration Manager by typing sqlservermanager11.msc, and pressing [ENTER].

Navigate to SQL Server Configuration Manager >> SQL Server Network Configuration. Right click on Protocols for [NAME OF INSTANCE], where [NAME OF INSTANCE] is a placeholder for the SQL Server instance name, and click on Properties.

On the Flags tab, if Force Encryption is set to "YES", examine the certificate used on the Certificate tab.

If Force Encryption is set, a DoD Certificate is not utilized, and a physical encryption measure is utilized, examine the physical encryption devices to determine the following:

1. The plaintext connection to the database server is afforded the highest protections, allowing no access to unauthorized or non-cleared personnel.
2. The encryption device is configured to pass traffic to only the specific IP addresses as identified by the database documentation.
3. The encryption keys utilized are current and valid keys.
4. The keys utilized meet approved organizationally defined compliant algorithms.

If any of the preceding requirements is not met, this is a finding.

If Force Encryption is set to "NO" or a DoD Certificate is not utilized, and physical encryption measures are not utilized, this is a finding.'
  desc 'fix', 'Deploy organization-approved encryption to the SQL Server network connections.

Where physical network devices are used for encryption, set them up such that:

1. The plaintext connection to the database server is afforded the highest protections, allowing no access to unauthorized or non-cleared personnel.
2. The encryption device is configured to pass traffic to only the specific IP addresses as identified by the database documentation.
3. The encryption keys utilized are current and valid keys.
4. The keys utilized meet approved organizationally defined compliant algorithms.

Where SQL Server network encryption is used, open SQL Server Configuration Manager.  Navigate to SQL Server Configuration Manager >> SQL Server Network Configuration. Right click on Protocols for [NAME OF INSTANCE], where [NAME OF INSTANCE] is a placeholder for the SQL Server instance name, and click on Properties.  On the Flags tab, set Force Encryption to YES, provide a DoD certificate on the Certificate tab.'
  impact 0.7
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47562r9_chk'
  tag severity: 'high'
  tag gid: 'V-40907'
  tag rid: 'SV-53261r4_rule'
  tag stig_id: 'SQL2-00-022600'
  tag gtitle: 'SRG-APP-000264-DB-000136'
  tag fix_id: 'F-46189r4_fix'
  tag cci: ['CCI-002421']
  tag nist: ['SC-8 (1)']
end
