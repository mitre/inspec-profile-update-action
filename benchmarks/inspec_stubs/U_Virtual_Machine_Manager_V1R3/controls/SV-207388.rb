control 'SV-207388' do
  title 'The VMM must use multifactor authentication for network access to non-privileged accounts.'
  desc 'To assure accountability and prevent unauthenticated access, non-privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system. 

Multifactor authentication uses two or more factors to achieve authentication. 

Factors include: 
(i) Something you know (e.g., password/PIN); 
(ii) Something you have (e.g., cryptographic identification device, token); or 
(iii) Something you are (e.g., biometric). 

A non-privileged account is any VMM account with authorizations of a non-privileged user. 

Network access is any access to an application by a user (or process acting on behalf of a user) where said access is obtained through a network connection.

The DoD CAC with DoD-approved PKI is an example of multifactor authentication.'
  desc 'check', 'Verify the VMM uses multifactor authentication for network access to non-privileged accounts.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to use multifactor authentication for network access to non-privileged accounts.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7645r365574_chk'
  tag severity: 'medium'
  tag gid: 'V-207388'
  tag rid: 'SV-207388r378853_rule'
  tag stig_id: 'SRG-OS-000106-VMM-000520'
  tag gtitle: 'SRG-OS-000106'
  tag fix_id: 'F-7645r365575_fix'
  tag 'documentable'
  tag legacy: ['V-56977', 'SV-71237']
  tag cci: ['CCI-000766']
  tag nist: ['IA-2 (2)']
end
