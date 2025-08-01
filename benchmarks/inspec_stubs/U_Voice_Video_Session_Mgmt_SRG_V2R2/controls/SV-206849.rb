control 'SV-206849' do
  title 'The Voice Video Session Manager supporting Command and Control (C2) communications must associate multilevel precedence and preemption (MLPP) attributes when exchanged between unified capabilities (UC) system components.'
  desc 'If MLPP attributes are not associated with the information being transmitted between systems, then access control policies and information flows which depend on these MLPP attributes will not function and unauthorized access may result.

Without the implementation of safeguards which allocate network communication resources based on priority, network availability, and particularly high priority traffic, may be dropped or delayed. DoD relies on the implementation of MLPP to ensure that flag officers and senior staff are provided higher priority for communications than other users. For VoIP and videoconferencing systems, Voice Video Session Managers must communicate using protocols and services that provide expedited packets to users and other systems.'
  desc 'check', 'Verify the Voice Video Session Manager supporting C2 communications associates MLPP attributes when exchanged between UC system components.

If the Voice Video Session Manager supporting C2 communications does not associate MLPP attributes when exchanged between UC system components, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager supporting C2 communications to associate MLPP attributes when exchanged between UC system components.'
  impact 0.5
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7104r364736_chk'
  tag severity: 'medium'
  tag gid: 'V-206849'
  tag rid: 'SV-206849r508661_rule'
  tag stig_id: 'SRG-NET-000354-VVSM-00020'
  tag gtitle: 'SRG-NET-000354'
  tag fix_id: 'F-7104r364737_fix'
  tag 'documentable'
  tag legacy: ['V-62129', 'SV-76619']
  tag cci: ['CCI-002455', 'CCI-000366']
  tag nist: ['SC-16', 'CM-6 b']
end
