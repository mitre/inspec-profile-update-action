control 'SV-213967' do
  title 'Confidentiality of information during transmission is controlled through the use of an approved TLS version.'
  desc 'Transport Layer Security (TLS) encryption is a required security setting as a number of known vulnerabilities have been reported against Secure Sockets Layer (SSL) and earlier versions of TLS. Encryption of private information is essential to ensuring data confidentiality. If private information is not encrypted, it can be intercepted and easily read by an unauthorized party. SQL Server must use a FIPS-approved minimum TLS version 1.2, and all non-FIPS-approved SSL and TLS versions must be disabled. NIST SP 800-52 Rev.2 specifies the preferred configurations for government systems.

References:
TLS Support 1.2 for SQL Server: https://support.microsoft.com/en-us/kb/3135244 
TLS Registry Settings:  https://docs.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings'
  desc 'check', 'Access the SQL Server.
Access an administrator command prompt.
Type "regedit" to launch the Registry Editor.
 
Navigate to:
HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2

If this key does not exist, this is a finding.

Verify a REG_DWORD value of "0" for "DisabledByDefault" and a value of "1" for "Enabled" for both Client and Server.
 
Navigate to:
HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0
HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1
HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 2.0
HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 3.0

Under each key, verify a REG_DWORD value of "1" for "DisabledByDefault" and a value of "0" for "Enabled" for both Client and Server subkeys.
 
If any of the respective registry paths are non-existent or contain values other than specified above, this is a finding. If Vendor documentation supporting the configuration is provided, reduce this finding to a CAT 3.'
  desc 'fix', 'Important Note: Incorrectly modifying the Windows Registry can result in serious system errors. Before making any modifications, ensure you have a recent backup of the system and registry settings.

Access the SQL Server.
Access an administrator command prompt. 
Type "regedit" to launch the Registry Editor.
 
Enable TLS 1.2:
  
1.Navigate to the path HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols.
   a.If the "TLS 1.2" key does not exist, right-click "Protocols".
   b.Click "New".
   c.Click "Key".
   d.Type the name "TLS 1.2".

2.Navigate to the "TLS 1.2" subkey.
   a.If the subkey "Client" does not exist, right-click "TLS 1.2"
   b.Click "New".
   c.Click "Key".
   d.Type the name "Client".
   e.Repeat steps A – D for the "Server" subkey.

3.Navigate to the "Client" subkey.
   a.If the value "Enabled" does not exist, right-click on "Client".
   b.Click "New".
   c.Click "DWORD".
   d.Enter "Enabled" as the name.
   e.Repeat steps A-D for the value "DisabledByDefault".

4.Double-click "Enabled".

5.In Value Data, enter "1".

6.Click "OK".

7.Double-click "DisabledByDefault".

8.In Value Data, enter "0".

9.Click "OK".

10.Repeat steps 3 – 9 for the "Server" subkey.
 

Disable unwanted SSL/TLS protocol versions:

1.Navigate to the path HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols.
   a.If the "TLS 1.0" key does not exist, right-click "Protocols".
   b.Click "New".
   c.Click "Key".
   d.Type the name "TLS 1.0".

2.Navigate to the "TLS 1.0" subkey.
   a.If the subkey "Client" does not exist, right-click "TLS 1.0".
   b.Click "New".
   c.Click "Key".
   d.Type the name "Client".
   e.Repeat steps A – D for the "Server" subkey.

3.Navigate to the "Client" subkey.
   a.If the value "Enabled" does not exist, right-click on "Client".
   b.Click "New".
   c.Click "DWORD".
   d.Enter "Enabled" as the name.
   e.Repeat steps A-D for the value "DisabledByDefault".

4.Double-click "Enabled".

5.In Value Data, enter "0".

6.Click "OK".

7.Double-click "DisabledByDefault".

8.In Value Data, enter "1".

9.Click "OK".

10.Repeat steps 3 – 9 for the "Server" subkey.

11.Repeat steps 1 – 10 for "TLS 1.1", "SSL 2.0", and "SSL 3.0".'
  impact 0.7
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15184r822460_chk'
  tag severity: 'high'
  tag gid: 'V-213967'
  tag rid: 'SV-213967r879609_rule'
  tag stig_id: 'SQL6-D0-008300'
  tag gtitle: 'SRG-APP-000172-DB-000075'
  tag fix_id: 'F-15182r822461_fix'
  tag 'documentable'
  tag legacy: ['SV-106625', 'V-97521']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
