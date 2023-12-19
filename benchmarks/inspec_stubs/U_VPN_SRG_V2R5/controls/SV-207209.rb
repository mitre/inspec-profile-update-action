control 'SV-207209' do
  title 'The VPN Gateway must use multifactor authentication (e.g., DoD PKI) for network access to non-privileged accounts.'
  desc 'To assure accountability and prevent unauthenticated access, non-privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system.

Multifactor authentication uses two or more factors to achieve authentication. Use of password for user remote access for non-privileged account is not authorized.

Factors include:
(i) Something you know (e.g., password/PIN);
(ii) Something you have (e.g., cryptographic identification device, token); or
(iii) Something you are (e.g., biometric).

A non-privileged account is any information system account with authorizations of a non-privileged user.

Network access is any access to a network element by a user (or a process acting on behalf of a user) communicating through a network.

The DoD CAC with DoD-approved PKI is an example of multifactor authentication.'
  desc 'check', 'Verify the VPN Gateway uses multifactor authentication (e.g., DoD PKI) for network access to non-privileged accounts.

If the VPN Gateway does not use multifactor authentication (e.g., DoD PKI) for network access to non-privileged accounts, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to use multifactor authentication (e.g., DoD PKI) for network access to non-privileged accounts.'
  impact 0.7
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7469r378248_chk'
  tag severity: 'high'
  tag gid: 'V-207209'
  tag rid: 'SV-207209r608988_rule'
  tag stig_id: 'SRG-NET-000140-VPN-000500'
  tag gtitle: 'SRG-NET-000140'
  tag fix_id: 'F-7469r378249_fix'
  tag 'documentable'
  tag legacy: ['V-97089', 'SV-106227']
  tag cci: ['CCI-000766']
  tag nist: ['IA-2 (2)']
end
