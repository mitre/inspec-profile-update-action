control 'SV-254897' do
  title 'Multi-factor authentication must be enabled and enforced on the Tanium Server for all access and all accounts.'
  desc 'To ensure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses, except the following.

(i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and
(ii) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.

'
  desc 'check', '1. Access the Tanium Server interactively.
 
2. Log on to the TanOS console with the "tanadmin" user role.

3. Enter "2" to access the "Tanium Operations" menu. 

4. Enter "2" to access the "Tanium Configuration" Settings menu.  

5. Enter "1" to access the "Edit Tanium Server Settings" menu.

6. Validate the value for "ForceSOAPSSLClientCert" is set to "1".

7. Validate the following keys exist and are configured: 

7A. "ClientCertificateAuthField"
For example: 
X509v3 Subject Alternative Name.

7B. "ClientCertificateAuthRegex"
For example:
.*:\\s(\\d+)@.*
Note: This regex may vary. 

7C. "ClientCertificateAuth"
For example:
/opt/Tanium/TaniumServer/cac.pem

7D. "TrustedHostList"
For example:
Append 127.0.0.1 (for IPv4) and [::1] (for IPv6)

If the value for "ForceSOAPSSLClientCert" is not set to "1" and the remaining registry values are not configured, this is a finding.'
  desc 'fix', 'Use the vendor documentation titled "Multi-Factor Authentication" to implement correct configuration settings for this requirement.
 
Vendor documentation can be downloaded from the following URL: https://docs.tanium.com/platform_deployment_reference/platform_deployment_reference/smart_card_authentication.html#cac_Tanium_Appliance

1. Access the Tanium Server interactively.
 
2. Log on to the TanOS server with the tanadmin user role. 

3. Enter "2" to access the "Tanium Operations" menu. 

4. Enter "2" to access the "Tanium Configuration" Settings menu.  

5. Enter "1" to access the "Edit Tanium Server Settings" menu.

6. Validate the value for "ForceSOAPSSLClientCert" is set to "1".

7. Validate the following keys exist and are configured: 

7A. "ClientCertificateAuthField"
For example: 
X509v3 Subject Alternative Name.

7B. "ClientCertificateAuthRegex"
For example:
.*:\\s(\\d+)@.*
Note: This regex may vary. 

7C. "ClientCertificateAuth"
For example:
/opt/Tanium/TaniumServer/cac.pem
Note: The path name is case sensitive. 

7D. "TrustedHostList"
For example:
Append 127.0.0.1 (for IPv4) and [::1] (for IPv6).'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58510r867589_chk'
  tag severity: 'medium'
  tag gid: 'V-254897'
  tag rid: 'SV-254897r867591_rule'
  tag stig_id: 'TANS-AP-000195'
  tag gtitle: 'SRG-APP-000080'
  tag fix_id: 'F-58454r867590_fix'
  tag satisfies: ['SRG-APP-000080', 'SRG-APP-000148', 'SRG-APP-000149', 'SRG-APP-000150', 'SRG-APP-000151', 'SRG-APP-000152', 'SRG-APP-000156', 'SRG-APP-000391', 'SRG-APP-000392', 'SRG-APP-000402', 'SRG-APP-000403', 'SRG-APP-000005', 'SRG-APP-000004', 'SRG-APP-000002']
  tag 'documentable'
  tag cci: ['CCI-000056', 'CCI-000058', 'CCI-000060', 'CCI-000166', 'CCI-000764', 'CCI-000765', 'CCI-000766', 'CCI-000767', 'CCI-000768', 'CCI-001941', 'CCI-001953', 'CCI-001954', 'CCI-002009', 'CCI-002010']
  tag nist: ['AC-11 b', 'AC-11 a', 'AC-11 (1)', 'AU-10', 'IA-2', 'IA-2 (1)', 'IA-2 (2)', 'IA-2 (3)', 'IA-2 (4)', 'IA-2 (8)', 'IA-2 (12)', 'IA-2 (12)', 'IA-8 (1)', 'IA-8 (1)']
end
