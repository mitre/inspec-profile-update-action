control 'SV-222526' do
  title 'The application must use multifactor (e.g., CAC, Alt. Token) authentication for network access to non-privileged accounts.'
  desc 'To assure accountability and prevent unauthenticated access, non-privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system.

Multifactor authentication uses two or more factors to achieve authentication.

Factors include:

(i) Something you know (e.g., password/PIN);
(ii) Something you have (e.g., cryptographic identification device, CAC/SIPRNet token); or
(iii) Something you are (e.g., biometric).

A non-privileged account is any information system account with authorizations of a non-privileged user.

Network access is any access to an application by a user (or process acting on behalf of a user) where said access is obtained through a network connection.

Applications integrating with the DoD Active Directory and utilize the DoD CAC are an example of compliant multifactor authentication solutions.'
  desc 'check', 'Review the application documentation and interview the application administrator to identify application access methods.

If the application is not PK-enabled due to the hosted data being publicly releasable, this check is not applicable.

Ask the application administrator to log on to the application. Have the application admin use their non-privileged credentials.

Validate the application prompts the user to provide a certificate from the CAC.

Validate the application requests the user to input their CAC PIN. 

If the application allows access without requiring a CAC or Alt. Token, this is a finding.'
  desc 'fix', 'Configure the application to require CAC or Alt. Token authentication for non-privileged network access to non-privileged accounts.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24196r493486_chk'
  tag severity: 'medium'
  tag gid: 'V-222526'
  tag rid: 'SV-222526r508029_rule'
  tag stig_id: 'APSC-DV-001580'
  tag gtitle: 'SRG-APP-000150'
  tag fix_id: 'F-24185r493487_fix'
  tag 'documentable'
  tag legacy: ['SV-84157', 'V-69535']
  tag cci: ['CCI-000766']
  tag nist: ['IA-2 (2)']
end
