control 'SV-233081' do
  title 'The container platform must use multifactor authentication for local access to privileged accounts.'
  desc 'To ensure accountability and prevent unauthenticated access, privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system.

Multifactor authentication is defined as using two or more factors to achieve authentication.

Factors include: 
(i) Something a user knows (e.g., password/PIN); 
(ii) Something a user has (e.g., cryptographic identification device, token); or 
(iii) Something a user is (e.g., biometric).

A privileged account is defined as an information system account with authorizations of a privileged user.

Local access is defined as access to an organizational information system by a user (or process acting on behalf of a user) communicating through a direct connection without the use of a network.'
  desc 'check', 'Review the container platform configuration to determine if multifactor authentication is used for local access to privileged accounts. 

If multifactor authentication for local access to privileged accounts is not being used, this is a finding.'
  desc 'fix', 'Configure the container platform to use multifactor authentication for local access to privileged accounts.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36017r598879_chk'
  tag severity: 'medium'
  tag gid: 'V-233081'
  tag rid: 'SV-233081r599509_rule'
  tag stig_id: 'SRG-APP-000151-CTR-000365'
  tag gtitle: 'SRG-APP-000151'
  tag fix_id: 'F-35985r598880_fix'
  tag 'documentable'
  tag cci: ['CCI-000767']
  tag nist: ['IA-2 (3)']
end
