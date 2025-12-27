control 'SV-243096' do
  title 'The vCenter Server must use unique service accounts when applications connect to vCenter.'
  desc 'In order to not violate non-repudiation (i.e., deny the authenticity of who is connecting to vCenter), when applications need to connect to vCenter they must use unique service accounts.'
  desc 'check', 'Verify that each external application that connects to vCenter has a unique service account dedicated to that application. 

For example, there should be separate accounts for Log Insight, Operations Manager, or anything else that requires an account to access vCenter.

If any application shares a service account that is used to connect to vCenter, this is a finding.'
  desc 'fix', 'For applications sharing service accounts, create a new service account to assign to the application so that no application shares a service account with another.

When standing up a new application that requires access to vCenter, always create a new service account prior to installation and grant only the permissions needed for that application.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46371r719529_chk'
  tag severity: 'medium'
  tag gid: 'V-243096'
  tag rid: 'SV-243096r879887_rule'
  tag stig_id: 'VCTR-67-000034'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-46328r719530_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
