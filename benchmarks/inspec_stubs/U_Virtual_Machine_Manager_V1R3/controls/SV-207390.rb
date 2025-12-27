control 'SV-207390' do
  title 'The VMM must use multifactor authentication for local access to non-privileged accounts.'
  desc 'To assure accountability, prevent unauthenticated access, and prevent misuse of the system, privileged users must utilize multifactor authentication for local access. 

Multifactor authentication is defined as using two or more factors to achieve authentication. 

Factors include: 
(i) Something you know (e.g., password/PIN); 
(ii) Something you have (e.g., cryptographic identification device or token); or 
(iii) Something you are (e.g., biometric). 

A non-privileged account is defined as a VMM account with authorizations of a regular or non-privileged user. 

Local access is defined as access to an organizational VMM by a user (or process acting on behalf of a user) communicating through a direct connection without the use of a network.

The DoD CAC with DoD-approved PKI is an example of multifactor authentication.'
  desc 'check', 'Verify the VMM uses multifactor authentication for local access to non-privileged accounts.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to use multifactor authentication for local access to non-privileged accounts.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7647r365580_chk'
  tag severity: 'medium'
  tag gid: 'V-207390'
  tag rid: 'SV-207390r378859_rule'
  tag stig_id: 'SRG-OS-000108-VMM-000540'
  tag gtitle: 'SRG-OS-000108'
  tag fix_id: 'F-7647r365581_fix'
  tag 'documentable'
  tag legacy: ['V-56981', 'SV-71241']
  tag cci: ['CCI-000768']
  tag nist: ['IA-2 (4)']
end
