control 'SV-233163' do
  title 'Container images instantiated by the container platform must execute using least privileges.'
  desc 'Containers running within the container platform must execute as non-privileged. When a container can execute as a privileged container, the privileged container is also a privileged user within the hosting system, and the hosting system becomes a major security risk. It is important for the container platform runtime to validate the container user and disallow instantiation if the container is trying to execute with more privileges than required, as a privileged user, or is trying to perform a privilege escalation.

When privileged access is necessary for a container, a new policy for execution should be written for the container. The default behavior must not give containers privileged execution.

Examples of privileged users are root, admin, and default service accounts for the container platform.'
  desc 'check', 'Review documentation and configuration to determine if the container platform disallows instantiation of containers trying to execute with more privileges than required or with privileged permissions. 

If the container platform does not block containers requesting privileged permissions, privilege escalation, or allows containers to have more privileges than required, this is a finding.'
  desc 'fix', 'Configure the container platform to block instantiation with no more privileges than necessary.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36099r599618_chk'
  tag severity: 'medium'
  tag gid: 'V-233163'
  tag rid: 'SV-233163r599619_rule'
  tag stig_id: 'SRG-APP-000342-CTR-000775'
  tag gtitle: 'SRG-APP-000342'
  tag fix_id: 'F-36067r599126_fix'
  tag 'documentable'
  tag cci: ['CCI-002233']
  tag nist: ['AC-6 (8)']
end
