control 'SV-95603' do
  title 'AAA Services must be configured to require multifactor authentication using Personal Identity Verification (PIV) credentials for authenticating privileged user accounts.'
  desc 'Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased. 

Multifactor authentication requires using two or more factors to achieve authentication. 

Factors include: 
(i) something a user knows (e.g., password/PIN); 
(ii) something a user has (e.g., cryptographic identification device, token); or 
(iii) something a user is (e.g., biometric). 

A privileged account is defined as an information system account with authorizations of a privileged user. 

Network access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area network, or the Internet).'
  desc 'check', 'Verify AAA Services are configured to require multifactor authentication using PIV credentials for authenticating privileged user accounts. Although the Common Access Card (CAC) is a PIV credential, it should not be used for privileged accounts, but rather only for non-privileged accounts. Administrative smart cards and tokens, separate from the CAC, are the preferred solution for privileged accounts.

If AAA Services are not configured to require multifactor authentication using PIV credentials for authenticating privileged user accounts, this is a finding.'
  desc 'fix', 'Configure AAA Services to require multifactor authentication using PIV credentials for authenticating privileged user accounts. Although the CAC is a PIV credential, it should not be used for privileged accounts, but rather only for non-privileged accounts.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80631r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80893'
  tag rid: 'SV-95603r1_rule'
  tag stig_id: 'SRG-APP-000149-AAA-000400'
  tag gtitle: 'SRG-APP-000149-AAA-000400'
  tag fix_id: 'F-87749r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000765']
  tag nist: ['IA-2 (1)']
end
