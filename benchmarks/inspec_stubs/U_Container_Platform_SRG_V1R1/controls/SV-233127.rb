control 'SV-233127' do
  title 'The container platform must prohibit containers from accessing privileged resources.'
  desc 'Containers images instantiated within the container platform may request access to host system resources. Access to privileged resources can allow for unauthorized and unintended transfer of information, but in some cases, these resources may be needed for the service being offered by the container. By default, containers should be denied instantiation when privileged system resources are requested and granted only after approval has been given.

When access to privileged resources is necessary for a container, a new policy for execution should be written for the container. The default behavior must not give containers privileged access to host system resources.

Examples of system resources that should be protected are kernel namespaces and host system sensitive directories such as /etc and /usr.'
  desc 'check', 'Review documentation and configuration to determine if the container platform disallows instantiation of containers trying to access host system privileged resources. 

If the container platform does not block containers requesting host system privileged resources, this is a finding.'
  desc 'fix', 'Configure the container platform to block instantiation of containers requesting access to host system-privileged resources.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36063r599606_chk'
  tag severity: 'medium'
  tag gid: 'V-233127'
  tag rid: 'SV-233127r599607_rule'
  tag stig_id: 'SRG-APP-000243-CTR-000595'
  tag gtitle: 'SRG-APP-000243'
  tag fix_id: 'F-36031r599018_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
