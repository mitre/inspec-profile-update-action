control 'SV-215721' do
  title 'The BIG-IP APM module must use multifactor authentication for network access to non-privileged accounts.'
  desc 'To assure accountability and prevent unauthenticated access, non-privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system.

Multifactor authentication uses two or more factors to achieve authentication. Factors include: 

1) Something you know (e.g., password/PIN); 

2) Something you have (e.g., cryptographic, identification device, token); and 

3) Something you are (e.g., biometric).

Non-privileged accounts are not authorized on the network element regardless of configuration.

Network access is any access to an application by a user (or process acting on behalf of a user) where said access is obtained through a network connection.

The DoD CAC with DoD-approved PKI is an example of multifactor authentication.

This requirement applies to ALGs that provide user authentication intermediary services.'
  desc 'check', 'If the BIG-IP APM module does not provide user authentication intermediary services, this is not applicable.

Verify the BIG-IP APM is configured to use multifactor authentication for network access to non-privileged accounts.

Verify the BIG-IP APM module is configured as follows:

Navigate to the BIG-IP System manager >> Access Policy >> Access Profiles.

Click "Edit..." in the "Access Policy" column for an Access Profile used for granting access.

Verify the Access Profile is configured to use multifactor authentication for network access to non-privileged accounts.

If the BIG-IP APM module is not configured to use multifactor authentication for network access to non-privileged accounts, this is a finding.'
  desc 'fix', 'If user authentication intermediary services are provided, configure an access policy in the BIG-IP APM module to use multifactor authentication for network access to non-privileged accounts.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Access Policy Manager 11.x'
  tag check_id: 'C-16914r290409_chk'
  tag severity: 'medium'
  tag gid: 'V-215721'
  tag rid: 'SV-215721r557355_rule'
  tag stig_id: 'F5BI-AP-000079'
  tag gtitle: 'SRG-NET-000140-ALG-000094'
  tag fix_id: 'F-16912r290410_fix'
  tag 'documentable'
  tag legacy: ['SV-74463', 'V-60033']
  tag cci: ['CCI-000766']
  tag nist: ['IA-2 (2)']
end
