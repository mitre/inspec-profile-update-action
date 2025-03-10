control 'SV-253539' do
  title 'Prisma Cloud Compute must be configured to require local user accounts to use x.509 multifactor authentication.'
  desc 'Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased.

Multifactor authentication requires using two or more factors to achieve authentication.

Factors include: 
(i) something a user knows (e.g., password/PIN); 
(ii) something a user has (e.g., cryptographic identification device, token); or 
(iii) something a user is (e.g., biometric).

User access to Prisma Cloud Compute must use multifactor (x.509 based) authentication.

'
  desc 'check', %q(Navigate to Prisma Cloud Compute Console's >> Manage >> Authentication >> System Certificate tab. 

If not performing direct smart card authentication to the console, this is not a finding.

If performing direct smart card authentication to the console:

Revocation block: If "Enable certificate revocation checking" is set to "Off", this is a finding.

Show Advanced certificate configuration:
- In the "Certificate-based authentication to Console" block, verify the issuing CA(s) of the end users' certificates are within the Console CA certificate(s) field. 
- If there is no users' certificates, this is a finding. 

Click the "Users" tab.

Review accounts with Authentication method "Local".

If the local user account's name does not match the user's x.509 certificate's subjectName or the subject alternative name's PrincipalName value, this is a finding.)
  desc 'fix', %q(Navigate to Prisma Cloud Compute Console's >> Manage >> Authentication >> System Certificate tab.

Revocation block: Set "Enable certificate revocation checking" to "On" and click "Save".

In the "Certificate-based authentication to Console" block, import the smart card's issuing CA's chain of trust to the Console CA certificate(s) field. Click "Save".

Click the "Users" tab. (Accounts cannot be edited. They must be removed and recreated correctly.)

Delete account:
- Click the three-dot menu. 
- Click "Delete" and confirm "Delete User".

Create a local user account where the local user account name matches the user's x.509 certificate's subjectName or subject alternative name's PrincipalName value:
- Click "+Add user".
  Authentication Source = Local
  Username = subject alternative name's PrincipalName value
  Password = random password that is not given to the user
- Assign Role.
- Click "Save".)
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Prisma Cloud Compute'
  tag check_id: 'C-56991r840453_chk'
  tag severity: 'medium'
  tag gid: 'V-253539'
  tag rid: 'SV-253539r840455_rule'
  tag stig_id: 'CNTR-PC-000750'
  tag gtitle: 'SRG-APP-000177-CTR-000465'
  tag fix_id: 'F-56942r840454_fix'
  tag satisfies: ['SRG-APP-000177-CTR-000465', 'SRG-APP-000391-CTR-000935', 'SRG-APP-000401-CTR-000965', 'SRG-APP-000402-CTR-000970', 'SRG-APP-000605-CTR-001380']
  tag 'documentable'
  tag cci: ['CCI-000187', 'CCI-001857', 'CCI-001953', 'CCI-001991', 'CCI-002009']
  tag nist: ['IA-5 (2) (a) (2)', 'AU-5 (2)', 'IA-2 (12)', 'IA-5 (2) (d)', 'IA-8 (1)']
end
