control 'SRG-NET-000354-VVSM-00101_rule' do
  title 'The Unified Communications Session Manager supporting Command and Control (C2) communications must associate multilevel precedence and preemption (MLPP) attributes when exchanged between unified capabilities (UC) system components.'
  desc 'If MLPP attributes are not associated with the information being transmitted between systems, then access control policies and information flows which depend on these MLPP attributes will not function and unauthorized access may result.

Without the implementation of safeguards which allocate network communication resources based on priority, network availability, and particularly high priority traffic, may be dropped or delayed. DOD relies on the implementation of MLPP to ensure that flag officers and senior staff are provided higher priority for communications than other users. For VoIP and videoconferencing systems, Unified Communications Session Managers must communicate using protocols and services that provide expedited packets to users and other systems.'
  desc 'check', 'Verify the Unified Communications Session Manager supporting C2 communications associates MLPP attributes when exchanged between UC system components.

If the Unified Communications Session Manager supporting C2 communications does not associate MLPP attributes when exchanged between UC system components, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager supporting C2 communications to associate MLPP attributes when exchanged between UC system components.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000354-VVSM-00101_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000354-VVSM-00101'
  tag rid: 'SRG-NET-000354-VVSM-00101_rule'
  tag stig_id: 'SRG-NET-000354-VVSM-00101'
  tag gtitle: 'SRG-NET-000354-VVSM-00101'
  tag fix_id: 'F-SRG-NET-000354-VVSM-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-002455']
  tag nist: ['SC-16']
end
