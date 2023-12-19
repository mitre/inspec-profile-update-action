control 'SV-250994' do
  title 'MobileIron Sentry, for PKI-based authentication, must be configured to map validated certificates to unique user accounts.'
  desc 'Without mapping the PKI certificate to a unique user account, the ability to determine the identities of individuals or the status of their non-repudiation is considerably impacted during forensic analysis. A strength of using PKI as MFA is that it can help ensure only the assigned individual is using their associated user account. This can only be accomplished if the network device is configured to enforce the relationship which binds PKI certificates to unique user accounts.

Local accounts (accounts created, stored, and maintained locally on the network device) should be avoided in lieu of using a centrally managed directory service. Local accounts empower the same workgroup who will be operating the network infrastructure to also control and manipulate access methods, thus creating operational autonomy. This undesirable approach breaks the concept of separation of duties. Additionally, local accounts are susceptible to poor cyber hygiene because they create another user database that must be maintained by the operator, whose primary focus is on running the network. Such examples of poor hygiene include dormant accounts that are not disabled or deleted, employees who have left the organization but whose accounts are still present, periodic password and hash rotation, password complexity shortcomings, increased exposure to insider threat, etc. For reasons such as this, local users on network devices are frequently the targets of cyber-attacks. Instead, organizations should explore examples of centrally managed account services. These examples include the implementation of AAA concepts like the use of external RADIUS and LDAP directory service brokers.'
  desc 'check', 'Verify that an EDIPI is mapped to the Sentry Admin user accounts. 

1. Log in to the Sentry System Manager.
2. Verify "Certificate Based Authentication" under Security Tab >> Sign-In Authentication.
3. Verify that a Certificate Attribute Mapping is mapped to EDIPI.
4. Go to Security tab >> Local Users. Click on an active Local User and configure an EDIPI.
5. Click "Apply".
6. Repeat step 4 for all local users.

If EDIPI is not mapped to the Sentry Admin user accounts, this is a finding.'
  desc 'fix', 'Ensure that an EDIPI is mapped to the Sentry Admin user accounts. 

1. Log in to the Sentry System Manager.
2. Ensure "Certificate Based Authentication" under Security Tab >> Sign-In Authentication.
3. Ensure that a Certificate Attribute Mapping is mapped to EDIPI.
4. Go to Security tab >> Local Users. Click on an active Local User and configure an EDIPI.
5. Click "Apply".
6. Repeat step for 4 for all local users.'
  impact 0.7
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x NDM'
  tag check_id: 'C-54429r802202_chk'
  tag severity: 'high'
  tag gid: 'V-250994'
  tag rid: 'SV-250994r802204_rule'
  tag stig_id: 'MOIS-ND-000510'
  tag gtitle: 'SRG-APP-000177-NDM-000263'
  tag fix_id: 'F-54383r802203_fix'
  tag 'documentable'
  tag cci: ['CCI-000166', 'CCI-000187', 'CCI-000764']
  tag nist: ['AU-10', 'IA-5 (2) (a) (2)', 'IA-2']
end
