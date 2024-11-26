control 'SRG-NET-000226-VVSM-00101_rule' do
  title 'The Unified Communications Session Manager supporting Command and Control (C2) communications must validate the integrity of transmitted multilevel precedence and preemption (MLPP) attributes.'
  desc 'If MLPP attributes are not associated with the information being transmitted between components, then access control policies and information flows which depend on these MLPP attributes will not function and unauthorized access may result. When data is exchanged, the MLPP attributes associated with this data must be validated to ensure the data has not been changed.

Without the implementation of safeguards which allocate network communication resources based on priority, network availability, and particularly high priority traffic, may be dropped or delayed. DOD relies on the implementation of MLPP to ensure that flag officers and senior staff are provided higher priority for communications than other users. For VoIP and videoconferencing systems, Unified Communications Session Managers must communicate using protocols and services that provide expedited packets to users and other systems.'
  desc 'check', 'Verify the Unified Communications Session Manager supporting C2 communications validates the integrity of transmitted MLPP attributes.

If the Unified Communications Session Manager supporting C2 communications does not validate the integrity of transmitted MLPP attributes, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager supporting C2 communications to validate the integrity of transmitted MLPP attributes.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000226-VVSM-00101_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000226-VVSM-00101'
  tag rid: 'SRG-NET-000226-VVSM-00101_rule'
  tag stig_id: 'SRG-NET-000226-VVSM-00101'
  tag gtitle: 'SRG-NET-000226-VVSM-00101'
  tag fix_id: 'F-SRG-NET-000226-VVSM-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-001158']
  tag nist: ['SC-16 (1)']
end
