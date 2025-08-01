control 'SRG-NET-000140-VVEP-00010_rule' do
  title 'The Unified Communications Endpoint must use multifactor authentication for network access to nonprivileged accounts.'
  desc 'To ensure accountability and prevent unauthenticated access, nonprivileged users must use multifactor authentication to prevent potential misuse and compromise of the system. 

Multifactor authentication uses two or more factors to achieve authentication. 

Factors include:
(i) Something you know (e.g., password/PIN); 
(ii) Something you have (e.g., cryptographic identification device, token); or 
(iii) Something you are (e.g., biometric). 

The DOD CAC with DOD-approved PKI is an example of multifactor authentication. 

Multifactor authentication is implemented most often with software type endpoints, as this can be implemented at the operating system level. More recent advances in hardware may allow implementation at the hardware endpoint.'
  desc 'check', 'Verify the Unified Communications Endpoint uses multifactor authentication for network access to nonprivileged accounts.

If the Unified Communications Endpoint does not use multifactor authentication for network access to nonprivileged accounts, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Endpoint to use multifactor authentication for network access to nonprivileged accounts.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000140-VVEP-00010_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000140-VVEP-00010'
  tag rid: 'SRG-NET-000140-VVEP-00010_rule'
  tag stig_id: 'SRG-NET-000140-VVEP-00010'
  tag gtitle: 'SRG-NET-000140-VVEP-00010'
  tag fix_id: 'F-SRG-NET-000140-VVEP-00010_fix'
  tag 'documentable'
  tag cci: ['CCI-000766']
  tag nist: ['IA-2 (2)']
end
