control 'SRG-NET-000098-VVSM-00101_rule' do
  title 'The Unified Communications Session Manager must protect session (call) records from unauthorized read access.'
  desc 'Auditing and logging are key components of any security architecture. Logging the actions of specific events provides a means to investigate an attack, recognize resource utilization or capacity thresholds, or to simply identify an improperly configured network element. Thus, it is imperative that the collected log data from the various network elements, as well as the auditing tools, be secured and can only be accessed by authorized personnel.'
  desc 'check', 'Verify the Unified Communications Session Manager protects session records from unauthorized read access.

If the Unified Communications Session Manager does not protect session records from unauthorized read access, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager to protect session records from unauthorized read access.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000098-VVSM-00101_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000098-VVSM-00101'
  tag rid: 'SRG-NET-000098-VVSM-00101_rule'
  tag stig_id: 'SRG-NET-000098-VVSM-00101'
  tag gtitle: 'SRG-NET-000098-VVSM-00101'
  tag fix_id: 'F-SRG-NET-000098-VVSM-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
