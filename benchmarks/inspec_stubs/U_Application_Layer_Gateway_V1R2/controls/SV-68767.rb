control 'SV-68767' do
  title 'The ALG providing user authentication intermediary services must use multifactor authentication for network access to non-privileged accounts.'
  desc 'To assure accountability and prevent unauthenticated access, non-privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system.

Multifactor authentication uses two or more factors to achieve authentication. Factors include: 

1) Something you know (e.g., password/PIN), 
2) Something you have (e.g., cryptographic, identification device, token), and 
3) Something you are (e.g., biometric)

Non-privileged accounts are not authorized access to the network element regardless of access method.

Network access is any access to an application by a user (or process acting on behalf of a user) where said access is obtained through a network connection.

Authenticating with a PKI credential and entering the associated PIN is an example of multifactor authentication.

This requirement applies to ALGs that provide user authentication intermediary services.'
  desc 'check', 'If the ALG does not provide user authentication intermediary services, this is not applicable.

Verify the ALG is configured to use multifactor authentication for network access to non-privileged accounts.

If the ALG does not use multifactor authentication for network access to non-privileged accounts, this is a finding.'
  desc 'fix', 'If user authentication intermediary services are provided, configure the ALG to use multifactor authentication for network access to non-privileged accounts.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55137r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54521'
  tag rid: 'SV-68767r1_rule'
  tag stig_id: 'SRG-NET-000140-ALG-000094'
  tag gtitle: 'SRG-NET-000140-ALG-000094'
  tag fix_id: 'F-59375r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000766']
  tag nist: ['IA-2 (2)']
end
