control 'SV-250733' do
  title 'Access to SSL certificates must be monitored.'
  desc 'The directory that contains the SSL certificates only needs to be accessed by the service account user on a regular basis. Occasionally, the vCenter Server system administrator might need to access it for support purposes.  The SSL certificate can be used to impersonate vCenter and decrypt the vCenter database password.'
  desc 'check', 'Ask the SA if event log monitoring is used to alert on non-service account access to the certificates directory.

If event log monitoring is not used, this is a finding.'
  desc 'fix', 'Set up Windows event log monitoring to alert on nonservice account access to the certificates directory.'
  impact 0.5
  ref 'DPMS Target VMware vCenter Server Version 5'
  tag check_id: 'C-54168r799887_chk'
  tag severity: 'medium'
  tag gid: 'V-250733'
  tag rid: 'SV-250733r799889_rule'
  tag stig_id: 'VCENTER-000013'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-54122r799888_fix'
  tag 'documentable'
  tag legacy: ['V-39551', 'SV-51409']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
