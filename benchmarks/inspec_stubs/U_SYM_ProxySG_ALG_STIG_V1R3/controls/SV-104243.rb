control 'SV-104243' do
  title 'Symantec ProxySG providing user authentication intermediary services must use multifactor authentication for network access to nonprivileged accounts.'
  desc 'To assure accountability and prevent unauthenticated access, nonprivileged users must use multifactor authentication to prevent potential misuse and compromise of the system.

Multifactor authentication uses two or more factors to achieve authentication. Factors include: 

1. Something you know (e.g., password/PIN) 
2. Something you have (e.g., cryptographic, identification device, token)
3. Something you are (e.g., biometric)

Nonprivileged accounts are not authorized access to the network element regardless of access method.

Network access is any access to an application by a user (or process acting on behalf of a user) where the access is obtained through a network connection.

Authenticating with a PKI credential and entering the associated PIN is an example of multifactor authentication.'
  desc 'check', 'Verify that a DoD-approved authentication server that uses multifactor authentication is configured.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Authentication.

If Symantec ProxySG providing user authentication intermediary services does not use multifactor authentication for network access to nonprivileged accounts, this is a finding.'
  desc 'fix', 'Configure a DoD-approved authentication server that uses multifactor authentication.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Authentication >> Windows Domain.
3. Click "Add New Domain" and follow prompts to join the Windows Domain.'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93475r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94289'
  tag rid: 'SV-104243r1_rule'
  tag stig_id: 'SYMP-AG-000370'
  tag gtitle: 'SRG-NET-000140-ALG-000094'
  tag fix_id: 'F-100405r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000766']
  tag nist: ['IA-2 (2)']
end
