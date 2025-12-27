control 'SV-95969' do
  title 'The WebSphere Application Server must protect log information from unauthorized modification.'
  desc 'WebSphere uses role-based access controls to restrict access to log data. To take advantage of this capability, WebSphere administrators must identify specific users and place them into their respective roles. The auditor role is used for controlling access to logs.'
  desc 'check', 'Review System Security Plan and the system documentation.

Identify the home folder and user account for the WebSphere installation.

Log on to the operating system that is hosting the WebSphere application server. By default, WebSphere will be installed in the "/opt/IBM/Websphere" folder on UNIX like systems and in the "C:\\Program Files\\IBM\\Websphere\\" folder on Windows systems.

On UNIX systems, verify file permissions for the "WebSphere" folder are set to "770" for the WebSphere user, group and other. Permissions do not propagate to sub-folders.

On Windows systems, verify file permissions for "WebSphere" folder allow SYSTEM, WebSphere User, and Admin Group full control. Permissions do not propagate to sub-folders.

If file permissions exceed these restrictions, this is a finding.'
  desc 'fix', 'On the system hosting the WebSphere application server, log on to the operating system with admin rights.

Navigate to the "WebSphere" folder, change permissions on the folder. Do not propagate permissions to sub-folders.

For UNIX systems: set "WebSphere folder" permissions to "770".

For Windows systems: set "WebSphere folder" permission to allow full control for SYSTEM, WebSphere user, and Admin Group. Do not propagate permissions to sub-folders.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80951r2_chk'
  tag severity: 'medium'
  tag gid: 'V-81255'
  tag rid: 'SV-95969r1_rule'
  tag stig_id: 'WBSP-AS-000750'
  tag gtitle: 'SRG-APP-000119-AS-000079'
  tag fix_id: 'F-88035r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
