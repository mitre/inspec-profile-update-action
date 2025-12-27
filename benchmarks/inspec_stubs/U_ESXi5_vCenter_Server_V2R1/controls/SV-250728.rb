control 'SV-250728' do
  title 'The Web datastore browser must be disabled, unless required for normal day-to-day operations.'
  desc 'The Web datastore browser enables viewing of all the datastores associated with the vSphere deployment, including all folders and files, such as VM files. This functionality is controlled by the organization-specific, user permissions on vCenter Server.'
  desc 'check', "If the Web datastore browser is required for normal, daily operational tasks, this check is not applicable.

Verify the Web datastore browser is disabled:
Determine the location of the vpxd.cfg file on the vCenter Server's Windows OS host.
Edit the file and locate the <vpxd> </vpxd> element.
Ensure the following element is set. <enableHttpDatastoreAccess>false</enableHttpDatastoreAccess> 

If the Web datastore browser is not disabled, this is a finding."
  desc 'fix', 'If the Web datastore browser is enabled and required for normal, daily operational tasks, no fix is required.

Disable the Web datastore browser:
Determine the location of the vpxd.cfg file on the Windows host.
Edit the file and locate the <vpxd> ... </vpxd> element.
Ensure the following element is set <enableHttpDatastoreAccess>false</enableHttpDatastoreAccess> 

Restart the vCenter Service to ensure the config file change(s) are in effect.'
  impact 0.3
  ref 'DPMS Target VMware vCenter Server Version 5'
  tag check_id: 'C-54163r799872_chk'
  tag severity: 'low'
  tag gid: 'V-250728'
  tag rid: 'SV-250728r799874_rule'
  tag stig_id: 'VCENTER-000006'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-54117r799873_fix'
  tag 'documentable'
  tag legacy: ['SV-51404', 'V-39546']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
