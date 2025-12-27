control 'SV-250738' do
  title 'Access to SSL certificates must be restricted.'
  desc 'The SSL certificate can be used to impersonate vCenter and decrypt the vCenter database password. By default, only the service user account and the vCenter Server administrators can access the directory containing the SSL certificates. The directory that contains the SSL certificates only needs to be accessed by the service account user on a regular basis. Occasionally, when collecting data for support purposes, the vCenter Server system administrator might need to access it. The permissions should be checked on a regular basis to ensure they have not been changed to add unauthorized users.'
  desc 'check', 'Check the Windows file permission on the SSL certificate directory files are set so only the vCenter service account and authorized vCenter Server Administrators can access them. Verify the directory and all files within are only accessible to the service user (System) and authorized vCenter Server administrators. The location by default for vCenter this is C:\\ProgramData\\VMware\\VMware VirtualCenter\\SSL and for the Inventory Service SSL certificate is C:\\Program Files\\VMware\\Infrastructure\\Inventory Service\\ssl.

If the SSL certificate directory/files are not set so that only the vCenter service account and authorized vCenter Server Administrators can access them, this is a finding.'
  desc 'fix', 'Ensure the Windows file permission on the SSL certificate directory files are set so only the vCenter service account and authorized vCenter Server Administrators can access them. Ensure the directory and all files within are only accessible to the service user (System) and authorized vCenter Server administrators. The location by default for vCenter this is C:\\ProgramData\\VMware\\VMware VirtualCenter\\SSL and for the Inventory Service SSL certificate is C:\\Program Files\\VMware\\Infrastructure\\Inventory Service\\ssl.'
  impact 0.5
  ref 'DPMS Target VMware vCenter Server Version 5'
  tag check_id: 'C-54173r799902_chk'
  tag severity: 'medium'
  tag gid: 'V-250738'
  tag rid: 'SV-250738r799904_rule'
  tag stig_id: 'VCENTER-000019'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-54127r799903_fix'
  tag 'documentable'
  tag legacy: ['SV-51415', 'V-39557']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
