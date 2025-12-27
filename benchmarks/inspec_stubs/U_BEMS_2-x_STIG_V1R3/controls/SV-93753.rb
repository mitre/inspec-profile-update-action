control 'SV-93753' do
  title 'If the BlackBerry Docs service is installed on the BlackBerry Enterprise Mobility Server (BEMS), it must be configured to enable audit logs.'
  desc 'Logging must be used in order to track system activity, assist in diagnosing system issues, and provide evidence needed for forensic investigations post security incident.'
  desc 'check', 'This requirement is not applicable if the BlackBerry Docs service is not enabled on BEMS.

Verify audit logging is enabled for the BlackBerry Docs service as follows:

1. In the BEMS Dashboard, under "BlackBerry Services Configuration", click "Docs".
2. Click "Audit".
3. On the "Audit Settings" tab, verify "Enable Audit Logs" is selected.

If audit logging is not enabled for the BlackBerry Docs service, this is a finding.'
  desc 'fix', 'Enable audit logging for the BlackBerry Docs service as follows:

1. In the BEMS Dashboard, under "BlackBerry Services Configuration", click "Docs".
2. Click "Audit".
3. On the "Audit Settings" tab, select the "Enable Audit Logs" check box.
4. Click "Save".'
  impact 0.5
  ref 'DPMS Target BEMS 2.x'
  tag check_id: 'C-78635r1_chk'
  tag severity: 'medium'
  tag gid: 'V-79047'
  tag rid: 'SV-93753r1_rule'
  tag stig_id: 'BEMS-00-014700'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-85797r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
