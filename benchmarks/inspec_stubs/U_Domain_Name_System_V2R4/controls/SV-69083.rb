control 'SV-69083' do
  title 'The DNS server implementation must prevent unauthorized and unintended information transfer via shared system resources.'
  desc 'Preventing unauthorized information transfers mitigates the risk of information, including encrypted representations of information, produced by the actions of prior users/roles (or the actions of processes acting on behalf of prior users/roles) from being available to any current users/roles (or current processes) that obtain access to shared system resources (e.g., registers, main memory, hard disks) after those resources have been released back to information systems. The control of information in shared resources is also commonly referred to as object reuse and residual information protection. 

There may be shared resources with configurable protections (e.g., files on storage) that may be assessed on specific information system components. The purpose of this control is to prevent information, produced by the actions of a prior process (or the actions of a process acting on behalf of a prior user) from being available to any current DNS process that obtains access to a shared system resource (e.g., registers, main memory, secondary storage) after the resource has been released back to the information system. Control of information in shared resources is also referred to as object reuse.'
  desc 'check', 'Review the DNS vendor documentation and system configuration to determine if object reuse is protected. 

If object reuse is not protected, this is a finding.'
  desc 'fix', 'Configure the DNS system to protect object reuse to prevent unauthorized and unintended information transfer via shared system resources.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55459r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54837'
  tag rid: 'SV-69083r1_rule'
  tag stig_id: 'SRG-APP-000243-DNS-000034'
  tag gtitle: 'SRG-APP-000243-DNS-000034'
  tag fix_id: 'F-59695r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
