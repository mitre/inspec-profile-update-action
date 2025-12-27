control 'SV-95911' do
  title 'The WebSphere Application Server automatic repository checkpoints must be enabled to track configuration changes.'
  desc 'Without enabling repository checkpoints, you will not be able to determine the history of changes to WebSphere configuration files, and who made those changes.'
  desc 'check', 'Review System Security Plan documentation.

Identify the required "Automatic CheckPoint Depth" setting that has been defined.

From administrative console, click System administration >> Extended repository service.

If "Enable automatic repository checkpoints" is not selected or if the "automatic checkpoint depth" is less than the number of saves defined in the System Security Plan, this is a finding.'
  desc 'fix', 'From administrative console click System administration >> Extended repository service >> Enable automatic repository checkpoints.

Enter a "checkpoint depth value" according to the security plan.

Restart the DMGR and all the JVMs.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80867r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81197'
  tag rid: 'SV-95911r1_rule'
  tag stig_id: 'WBSP-AS-000120'
  tag gtitle: 'SRG-APP-000016-AS-000013'
  tag fix_id: 'F-87975r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
