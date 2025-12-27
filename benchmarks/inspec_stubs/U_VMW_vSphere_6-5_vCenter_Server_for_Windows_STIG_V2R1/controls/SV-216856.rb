control 'SV-216856' do
  title 'The vCenter Server for Windows must use unique service accounts when applications connect to vCenter.'
  desc 'In order to not violate non-repudiation (i.e., deny the authenticity of who is connecting to vCenter), when applications need to connect to vCenter they should use unique service accounts.'
  desc 'check', 'Verify that each external application that connects to vCenter has a unique service account dedicated to that application.  For example there should be separate accounts for Log Insight, Operations Manager, or anything else that requires an account to access vCenter.

If any application shares a service account that is used to connect to vCenter, this is a finding.'
  desc 'fix', 'For applications sharing service accounts create a new service account to assign to the application so that no application shares a service account with another.

When standing up a new application that requires access to vCenter always create a new service account prior to installation and grant only the permissions needed for that application.'
  impact 0.5
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18087r366282_chk'
  tag severity: 'medium'
  tag gid: 'V-216856'
  tag rid: 'SV-216856r612237_rule'
  tag stig_id: 'VCWN-65-000034'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-18085r366283_fix'
  tag 'documentable'
  tag legacy: ['V-94777', 'SV-104607']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
