control 'SV-250736' do
  title 'Revoked certificates must be removed from the vCenter Server.'
  desc "If revoked certificates are not removed from the vCenter Server, the user can be subject to a MiTM attack, which potentially might enable compromise through impersonation with the user's credentials to the vCenter Server system."
  desc 'check', 'To check the status of SSL certificates on vCenter Server, open the vSphere Client and connect to the vCenter Server and log in. In the Security Warning dialog, click View Certificate and check the Valid from mm/dd/yy to mm/dd/yy field for the expiry information. Click OK. If unable to determine the certificate status from the certificate details, ask the SA if there is a site procedure to ensure the monitoring and removal of revoked certificates from the vCenter Server Windows host. Use this procedure to check the vCenter Server/host for the presence of revoked certificates.

If a procedure does not exist and/or revoked certificates are found, this is a finding.'
  desc 'fix', 'If a site procedure to ensure the monitoring and removal of revoked certificates from the vCenter Server Windows host does not exist, create one. Check the vCenter Server/host for the presence of revoked certificates. Remove all revoked certificates.'
  impact 0.5
  ref 'DPMS Target VMware vCenter Server Version 5'
  tag check_id: 'C-54171r799896_chk'
  tag severity: 'medium'
  tag gid: 'V-250736'
  tag rid: 'SV-250736r799898_rule'
  tag stig_id: 'VCENTER-000017'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-54125r799897_fix'
  tag 'documentable'
  tag legacy: ['SV-51413', 'V-39555']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
