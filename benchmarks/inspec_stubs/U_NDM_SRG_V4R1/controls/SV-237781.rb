control 'SV-237781' do
  title 'The network device, for PKI-based authentication, must be configured to map validated certificates to unique user accounts.'
  desc 'Without mapping the PKI certificate to a unique user account, the ability to determine the identities of individuals or the status of their non-repudiation is considerably impacted during forensic analysis. A strength of using PKI as MFA is that it can help ensure only the assigned individual is using their associated user account. This can only be accomplished if the network device is configured to enforce the relationship which binds PKI certificates to unique user accounts.

Local accounts (accounts created, stored, and maintained locally on the network device) should be avoided in lieu of using a centrally managed directory service. Local accounts empower the same workgroup who will be operating the network infrastructure to also control and manipulate access methods, thus creating operational autonomy. This undesirable approach breaks the concept of separation of duties. Additionally, local accounts are susceptible to poor cyber hygiene because they create another user database that must be maintained by the operator, whose primary focus is on running the network. Such examples of poor hygiene include dormant accounts that are not disabled or deleted, employees who have left the organization but whose accounts are still present, periodic password and hash rotation, password complexity shortcomings, increased exposure to insider threat, etc. For reasons such as this, local users on network devices are frequently the targets of cyber-attacks. Instead, organizations should explore examples of centrally managed account services. These examples include the implementation of AAA concepts like the use of external RADIUS and LDAP directory service brokers.'
  desc 'check', 'If PKI-based authentication is not used as the MFA solution for interactive logins, this requirement is not applicable.

If the network device is configured to use a AAA service account, and the AAA broker is configured to map validated certificates to centralized user accounts on behalf of the network device, that will satisfy this objective. Because the responsibility for meeting this objective is transferred to the AAA broker, this requirement is not applicable for the local network device. This requirement may be verified by demonstration or configuration review.

Verify the network device is configured to map each validated certificate to a unique, centralized user account for all interactive users. If the network device is not configured to map each validated certificate to a unique, centralized user account for all interactive users, this is a finding.

Note: If local user accounts are used on the device, this requirement cannot be met in its entirety and it is a permanent finding. This may be the case if AO’s choose to accept the risk of using local accounts on network devices for small, isolated environments where centralized directory services are not available in the infrastructure or where they are not cost effective to implement and maintain. In such cases, this requirement can be mitigated to a CAT III if the network device is configured to map each validated certificate to a unique, local user account for all interactive users. 

Note: This requirement is not applicable to the emergency account of last resort nor for service accounts (non-interactive users). Examples of service accounts include remote service brokers such as AAA, syslog, etc.'
  desc 'fix', 'Configure the network device to use a AAA service account whereby the remote AAA broker will map the validated certificate used for PKI-based authentication to a centrally managed, interactive user account.

Alternatively, for organizations who choose to accept the risk and permanent finding, configure the network device to map the validated certificate used for PKI-based authentication to a unique, local, interactive user account.'
  impact 0.7
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-40991r663940_chk'
  tag severity: 'high'
  tag gid: 'V-237781'
  tag rid: 'SV-237781r663942_rule'
  tag stig_id: 'SRG-APP-000177-NDM-000263'
  tag gtitle: 'SRG-APP-000177'
  tag fix_id: 'F-40950r663941_fix'
  tag 'documentable'
  tag cci: ['CCI-000187', 'CCI-000764', 'CCI-000166']
  tag nist: ['IA-5 (2) (a) (2)', 'IA-2', 'AU-10']
end
