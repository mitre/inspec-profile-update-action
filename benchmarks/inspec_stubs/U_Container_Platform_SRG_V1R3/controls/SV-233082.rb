control 'SV-233082' do
  title 'The container platform must use multifactor authentication for local access to non-privileged accounts.'
  desc 'To ensure accountability, prevent unauthenticated access, and prevent misuse of the system, non-privileged users must utilize multi-factor authentication for local access.

Multifactor authentication is defined as using two or more factors to achieve authentication.

Factors include: 
(i) Something a user knows (e.g., password/PIN); 
(ii) Something a user has (e.g., cryptographic identification device, token); or 
(iii) Something a user is (e.g., biometric).

A non-privileged account is defined as an information system account with authorizations of a regular or non-privileged user.

Local access is defined as access to an organizational information system by a user (or process acting on behalf of a user) communicating through a direct connection without the use of a network.'
  desc 'check', 'Review the container platform configuration to determine if multifactor authentication is used for local access to non-privileged accounts. 

If multifactor authentication for local access to non-privileged accounts is not being used, this is a finding.'
  desc 'fix', 'Configure the container platform to use multifactor authentication for local access to non-privileged accounts.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36018r600733_chk'
  tag severity: 'medium'
  tag gid: 'V-233082'
  tag rid: 'SV-233082r600735_rule'
  tag stig_id: 'SRG-APP-000152-CTR-000370'
  tag gtitle: 'SRG-APP-000152'
  tag fix_id: 'F-35986r600734_fix'
  tag 'documentable'
  tag cci: ['CCI-000768']
  tag nist: ['IA-2 (4)']
end
