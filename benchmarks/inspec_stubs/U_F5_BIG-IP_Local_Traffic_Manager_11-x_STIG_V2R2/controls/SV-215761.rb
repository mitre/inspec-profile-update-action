control 'SV-215761' do
  title 'The BIG-IP Core implementation providing user authentication intermediary services must use multifactor authentication for network access to non-privileged accounts when granting access to virtual servers.'
  desc 'To assure accountability and prevent unauthenticated access, non-privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system.

Multifactor authentication uses two or more factors to achieve authentication. Factors include: 

1) Something you know (e.g., password/PIN); 
2) Something you have (e.g., cryptographic, identification device, token); and 
3) Something you are (e.g., biometric).

Non-privileged accounts are not authorized on the network element regardless of configuration.

Network access is any access to an application by a user (or process acting on behalf of a user) where said access is obtained through a network connection.

The DoD CAC with DoD-approved PKI is an example of multifactor authentication.

This requirement applies to ALGs that provide user authentication intermediary services.'
  desc 'check', 'If the BIG-IP Core does not provide user authentication intermediary services for virtual servers, this is not applicable.

When user authentication intermediary services, verify the BIG-IP Core is configured as follows:

Verify Virtual Server(s) in the BIG-IP LTM module are configured with an APM policy to use multifactor authentication for network access to non-privileged accounts.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify.

Verify under "Access Policy" section, that "Access Policy" has been set to use an APM access policy that uses multifactor authentication for network access to non-privileged accounts when granting access to virtual servers.

If the BIG-IP Core provides user authentication intermediary services and does not use multifactor authentication for network access to non-privileged accounts, this is a finding.'
  desc 'fix', 'If user authentication intermediary services are provided, configure the BIG-IP Core as follows: 

Configure a policy in the BIG-IP APM module to use multifactor authentication for network access to non-privileged accounts.

Apply APM policy to the applicable Virtual Server(s) in BIG-IP LTM module to use multifactor authentication for network access to non-privileged accounts when granting access to virtual servers.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16953r291096_chk'
  tag severity: 'medium'
  tag gid: 'V-215761'
  tag rid: 'SV-215761r557356_rule'
  tag stig_id: 'F5BI-LT-000079'
  tag gtitle: 'SRG-NET-000140-ALG-000094'
  tag fix_id: 'F-16951r291097_fix'
  tag 'documentable'
  tag legacy: ['V-60303', 'SV-74733']
  tag cci: ['CCI-000766']
  tag nist: ['IA-2 (2)']
end
