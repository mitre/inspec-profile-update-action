control 'SV-96095' do
  title 'The WebSphere Application Server must not generate LTPA keys automatically.'
  desc 'Automated LTPA key generation can create unplanned outages. Plan to change your LTPA keys during a scheduled outage. Distribute the new keys to all nodes in the cell and to all external systems/cells during this outage window.'
  desc 'check', 'If LTPA is not utilized, this is not applicable.

Request the documented process to manually regenerate the LTPA keys.

The time period for regeneration must be defined, documented, and accepted by the ISSO but must be performed at least annually.

Navigate to Security >> SSL Certificate and Key Management >> Key set groups >> Cell LTPAKeySetGroup.

If automatically generate keys is checked, this is a finding.'
  desc 'fix', 'Navigate to Security >> SSL Certificate and Key Management >> Key set groups >> Cell LTPAKeySetGroup.

Uncheck automatically generate keys.

Click "OK".

Click "Save".

Restart the "Deployment Manager".'
  impact 0.3
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-81091r1_chk'
  tag severity: 'low'
  tag gid: 'V-81381'
  tag rid: 'SV-96095r1_rule'
  tag stig_id: 'WBSP-AS-001520'
  tag gtitle: 'SRG-APP-000428-AS-000265'
  tag fix_id: 'F-88167r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002475']
  tag nist: ['SC-28 (1)']
end
