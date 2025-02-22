control 'SV-80685' do
  title 'The HP FlexFabric Switch must protect audit information from unauthorized deletion.'
  desc 'Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

If audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve. 

To ensure the veracity of audit data, the HP FlexFabric Switch must protect audit information from unauthorized deletion. This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Some commonly employed methods include: ensuring log files receive the proper file system permissions utilizing file system protections, restricting access, and backing up log data to ensure log data is retained. 

Network devices providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights the user enjoys in order to make access decisions regarding the deletion of audit data.'
  desc 'check', 'Determine if the HP FlexFabric Switch protects audit information from any type of unauthorized deletion with such methods as ensuring log files receive the proper file system permissions utilizing file system protections, restricting access to log data and backing up log data to ensure log data is retained, and leveraging user permissions and roles to identify the user accessing the data and the corresponding rights the user enjoys.

[HP] display local-user

Device management user security-user:
 State:                    Active
 Service type:             SSH/Terminal
 User group:               system
 Bind attributes:
 Authorization attributes:
  Work directory:          flash:
  User role list:          security-audit

If the HP FlexFabric Switch does not protect audit information from unauthorized deletion, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to protect audit information from unauthorized deletion:

[HP] local-user security-user
[HP-luser-manage-security-user]  authorization-attribute user-role security-audit
[HP-luser-manage-security-user] password
Password:xxxxxxxxxx
confirm: xxxxxxxxxx
[HP-luser-manage-security-user] service-type ssh terminal'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66841r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66195'
  tag rid: 'SV-80685r1_rule'
  tag stig_id: 'HFFS-ND-000038'
  tag gtitle: 'SRG-APP-000120-NDM-000237'
  tag fix_id: 'F-72271r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
