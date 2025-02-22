control 'SV-222528' do
  title 'The application must use multifactor (e.g., CAC, Alt. Token) authentication for local access to non-privileged accounts.'
  desc 'To assure accountability, prevent unauthenticated access, and prevent misuse of the system, privileged users must utilize multifactor authentication for local access.

Multifactor authentication is defined as: using two or more factors to achieve authentication.

Factors include:
(i) Something a user knows (e.g., password/PIN);
(ii) Something a user has (e.g., cryptographic identification device, token); or
(iii) Something a user is (e.g., biometric).

A non-privileged account is defined as an information system account with authorizations of a regular or non-privileged user.

Local access is defined as access to an organizational information system by a user (or process acting on behalf of a user) communicating through a direct connection without the use of a network.

Applications integrating with the DoD Active Directory and utilize the DoD CAC are examples of compliant multifactor authentication solutions.'
  desc 'check', 'Review the application documentation and interview the application administrator to identify application access methods.

If the application is not PK-enabled due to the hosted data being publicly releasable, this check is not applicable.

Ask the application administrator to log on to the application. Have the application admin use their non-privileged credentials.

Validate the application prompts the user to provide a certificate from the CAC.

Validate the application requests the user to input their CAC PIN.

If the application allows access without requiring a CAC or Alt. Token, this is a finding.'
  desc 'fix', 'Configure the application to require CAC or Alt. Token authentication for non-privileged network access.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24198r493492_chk'
  tag severity: 'medium'
  tag gid: 'V-222528'
  tag rid: 'SV-222528r879593_rule'
  tag stig_id: 'APSC-DV-001600'
  tag gtitle: 'SRG-APP-000152'
  tag fix_id: 'F-24187r493493_fix'
  tag 'documentable'
  tag legacy: ['SV-84161', 'V-69539']
  tag cci: ['CCI-000768']
  tag nist: ['IA-2 (4)']
end
