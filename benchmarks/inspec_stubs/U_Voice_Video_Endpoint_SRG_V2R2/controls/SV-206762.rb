control 'SV-206762' do
  title 'The Voice Video Endpoint used for videoconferencing must use multifactor authentication for network access.'
  desc 'To assure accountability and prevent unauthenticated access, users must utilize multifactor authentication to prevent potential misuse and compromise of the system. Multifactor authentication uses two or more factors to achieve authentication. 

Factors include:
(i) Something you know (e.g., password/PIN); 
(ii) Something you have (e.g., cryptographic identification device, token); or 
(iii) Something you are (e.g., biometric). 

Network access is any access to an application by a user (or process acting on behalf of a user) where said access is obtained through a network connection. The DoD CAC with DoD-approved PKI is an example of multifactor authentication. 

This does not apply to authentication for the purpose of configuring the device itself (i.e., device management).'
  desc 'check', 'If the Voice Video Endpoint is a hardware endpoint, this check procedure is Not Applicable.

Verify the Voice Video Endpoint used for videoconferencing uses multifactor authentication for network access.

If the Voice Video Endpoint used for videoconferencing does not use multifactor authentication for network access, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint used for videoconferencing to use multifactor authentication for network access.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7018r621698_chk'
  tag severity: 'medium'
  tag gid: 'V-206762'
  tag rid: 'SV-206762r604140_rule'
  tag stig_id: 'SRG-NET-000140-VVEP-00032'
  tag gtitle: 'SRG-NET-000140'
  tag fix_id: 'F-7018r363810_fix'
  tag 'documentable'
  tag legacy: ['SV-81237', 'V-66747']
  tag cci: ['CCI-000766']
  tag nist: ['IA-2 (2)']
end
