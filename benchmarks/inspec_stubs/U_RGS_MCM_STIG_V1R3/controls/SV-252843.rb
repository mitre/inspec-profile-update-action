control 'SV-252843' do
  title 'Rancher MCM must use a centralized user management solution to support account management functions. For accounts using password authentication, the container platform must use FIPS-validated SHA-2 or later protocol to protect the integrity of the password authentication process.'
  desc 'RBAC Integration and Authn/Authz

Centralized authentication services provide additional functionality fulfilling security requirements:
- Multi-factor authentication, which is compatible with Rancher MCM
- Disabling users after a period of time
- Storage and transmission of secure information is encrypted
- Secure authentication protocols such as LDAP over TLS, or LDAPS using FIPS 140-2 approved encryption modules
- PKI based authentication

Rancher MCM can integrate with external centralized authentication but does not offer a native solution. The authentication mechanism needs to be initially enabled and configured. The proxy authenticates users and forwards their requests to Kubernetes clusters using a service account.

'
  desc 'check', 'RBAC Integration and Authn/Authz

View and modify authentication settings through the Rancher MCM UI.

Navigate to Triple Bar Symbol(Global) >> Users & Authentication >> Auth Provider.

This screen shows the authentication mechanism that is configured. If no authentication mechanism is configured or disabled, this is a finding.'
  desc 'fix', 'RBAC Integration and Authn/Authz

Navigate to Triple Bar Symbol(Global) >> Users & Authentication >> Auth Provider.

From this screen the authentication mechanism can be selected and configured. 

This STIG is written and tested with KeyCloak and not included with Rancher MCM. Installation instructions for KeyCloak can be found here:

https://www.keycloak.org/getting-started/getting-started-kube'
  impact 0.7
  ref 'DPMS Target Rancher Government Solutions Multi-Cluster Manager'
  tag check_id: 'C-56299r819977_chk'
  tag severity: 'high'
  tag gid: 'V-252843'
  tag rid: 'SV-252843r879522_rule'
  tag stig_id: 'CNTR-RM-000030'
  tag gtitle: 'SRG-APP-000023-CTR-000055'
  tag fix_id: 'F-56249r819978_fix'
  tag satisfies: ['SRG-APP-000023-CTR-000055', 'SRG-APP-000024-CTR-000060', 'SRG-APP-000027-CTR-000075', 'SRG-APP-000029-CTR-000085', 'SRG-APP-000033-CTR-000095', 'SRG-APP-000038-CTR-000105', 'SRG-APP-000065-CTR-000115', 'SRG-APP-000099-CTR-000190', 'SRG-APP-000111-CTR-000220', 'SRG-APP-000118-CTR-000240', 'SRG-APP-000119-CTR-000245', 'SRG-APP-000120-CTR-000250', 'SRG-APP-000121-CTR-000255', 'SRG-APP-000122-CTR-000260', 'SRG-APP-000123-CTR-000265', 'SRG-APP-000126-CTR-000275', 'SRG-APP-000133-CTR-000310', 'SRG-APP-000148-CTR-000335', 'SRG-APP-000148-CTR-000340', 'SRG-APP-000148-CTR-000345', 'SRG-APP-000148-CTR-000350', 'SRG-APP-000149-CTR-000355', 'SRG-APP-000150-CTR-000360', 'SRG-APP-000156-CTR-000380', 'SRG-APP-000163-CTR-000395', 'SRG-APP-000164-CTR-000400', 'SRG-APP-000165-CTR-000405', 'SRG-APP-000166-CTR-000410', 'SRG-APP-000167-CTR-000415', 'SRG-APP-000168-CTR-000420', 'SRG-APP-000169-CTR-000425', 'SRG-APP-000170-CTR-000430', 'SRG-APP-000171-CTR-000435', 'SRG-APP-000172-CTR-000440', 'SRG-APP-000173-CTR-000445', 'SRG-APP-000174-CTR-000450', 'SRG-APP-000177-CTR-000465', 'SRG-APP-000178-CTR-000470', 'SRG-APP-000243-CTR-000595', 'SRG-APP-000317-CTR-000735', 'SRG-APP-000340-CTR-000770', 'SRG-APP-000345-CTR-000785', 'SRG-APP-000378-CTR-000880', 'SRG-APP-000378-CTR-000885', 'SRG-APP-000378-CTR-000890', 'SRG-APP-000380-CTR-000900', 'SRG-APP-000381-CTR-000905', 'SRG-APP-000384-CTR-000915', 'SRG-APP-000319-CTR-000745']
  tag 'documentable'
  tag cci: ['CCI-000015', 'CCI-000016', 'CCI-000044', 'CCI-000134', 'CCI-000154', 'CCI-000162', 'CCI-000163', 'CCI-000164', 'CCI-000187', 'CCI-000192', 'CCI-000193', 'CCI-000194', 'CCI-000195', 'CCI-000196', 'CCI-000197', 'CCI-000198', 'CCI-000199', 'CCI-000200', 'CCI-000205', 'CCI-000206', 'CCI-000213', 'CCI-000764', 'CCI-000765', 'CCI-000766', 'CCI-000795', 'CCI-001090', 'CCI-001350', 'CCI-001368', 'CCI-001403', 'CCI-001493', 'CCI-001494', 'CCI-001495', 'CCI-001499', 'CCI-001619', 'CCI-001764', 'CCI-001812', 'CCI-001813', 'CCI-001814', 'CCI-001941', 'CCI-002142', 'CCI-002235', 'CCI-002238']
  tag nist: ['AC-2 (1)', 'AC-2 (2)', 'AC-7 a', 'AU-3 e', 'AU-6 (4)', 'AU-9 a', 'AU-9 a', 'AU-9 a', 'IA-5 (2) (a) (2)', 'IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (b)', 'IA-5 (1) (c)', 'IA-5 (1) (c)', 'IA-5 (1) (d)', 'IA-5 (1) (d)', 'IA-5 (1) (e)', 'IA-5 (1) (a)', 'IA-6', 'AC-3', 'IA-2', 'IA-2 (1)', 'IA-2 (2)', 'IA-4 e', 'SC-4', 'AU-9 (3)', 'AC-4', 'AC-2 (4)', 'AU-9 a', 'AU-9', 'AU-9', 'CM-5 (6)', 'IA-5 (1) (a)', 'CM-7 (2)', 'CM-11 (2)', 'CM-5 (1) (a)', 'CM-5 (1)', 'IA-2 (8)', 'AC-2 (10)', 'AC-6 (10)', 'AC-7 b']
end
