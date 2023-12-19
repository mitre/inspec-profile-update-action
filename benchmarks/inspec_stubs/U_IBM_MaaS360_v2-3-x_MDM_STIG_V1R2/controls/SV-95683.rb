control 'SV-95683' do
  title 'Only authorized versions of the IBM MaaS360 server must be used.'
  desc 'The IBM MaaS360 V2 server is no longer supported by IBM and therefore, may contain security vulnerabilities.  The IBM MaaS360 V2 server is not authorized within the DoD.'
  desc 'check', 'Interview ISSO and IBM MaaS360 MDM system administrator.

Verify the site is not using the IBM MaaS360 V2 MDM or subscribing to a MaaS360 V2 MDM SaaS.

If the site is using the IBM MaaS360 V2 MDM or subscribing to a MaaS360 V2 MDM SaaS, this is a finding.'
  desc 'fix', 'Remove all versions of IBM MaaS360 V2 MDM or stop subscribing to a MaaS360 V2 MDM SaaS.'
  impact 0.7
  ref 'DPMS Target IBM MaaS360 v2.3.x MDM'
  tag check_id: 'C-81203r1_chk'
  tag severity: 'high'
  tag gid: 'V-80971'
  tag rid: 'SV-95683r1_rule'
  tag stig_id: 'M360-01-022200'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-88279r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
