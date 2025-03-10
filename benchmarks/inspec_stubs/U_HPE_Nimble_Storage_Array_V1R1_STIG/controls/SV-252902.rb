control 'SV-252902' do
  title 'HPE Nimble must be configured to disable HPE InfoSight.'
  desc 'DoD requires that the Mission Owner uses only the cloud services offering listed in either the FedRAMP or DISA PA DoD Cloud Catalog to host Unclassified, public-releasable, DoD information.

HPE InfoSight data collection is disabled by default in the HPE Nimble. Users must not enable it.'
  desc 'check', 'Navigate to Administration >> Alerts and Monitoring page of the storage array management interface. Verify the checkbox is not checked.

If HPE InfoSight is enabled, this is a finding.'
  desc 'fix', 'In HPE Nimble Storage arrays, data collection is disabled by default.

Navigate to Administration >> Alerts and Monitoring page of the storage array management interface. 

Uncheck the checkbox.'
  impact 0.5
  ref 'DPMS Target HPE Nimble Storage Array'
  tag check_id: 'C-56357r822430_chk'
  tag severity: 'medium'
  tag gid: 'V-252902'
  tag rid: 'SV-252902r822432_rule'
  tag stig_id: 'HPEN-NM-000221'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-56307r822431_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
