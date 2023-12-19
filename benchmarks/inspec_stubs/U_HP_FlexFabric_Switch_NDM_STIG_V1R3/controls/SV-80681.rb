control 'SV-80681' do
  title 'The HP FlexFabric Switch must protect audit information from any type of unauthorized read access.'
  desc 'Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. In addition, access to audit records provides information an attacker could use to his or her advantage.

To ensure the veracity of audit data, the information system and/or the HP FlexFabric Switch must protect audit information from any and all unauthorized read access.

This requirement can be achieved through multiple methods which will depend upon system architecture and design. Commonly employed methods for protecting audit information include least privilege permissions as well as restricting the location and number of log file repositories.

Additionally, network devices with user interfaces to audit records should not allow for the unfettered manipulation of or access to those records via the device interface. If the device provides access to the audit data, the device becomes accountable for ensuring audit information is protected from unauthorized access.'
  desc 'check', 'Determine if the HP FlexFabric Switch protects audit information from any type of unauthorized read access with such methods as least privilege permissions, restrictions on the location and number of log file repositories and not allowing for the unfettered manipulation of or access to audit records via switch interface.

[HP] display local-user

Device management user security-user:
 State:                    Active
 Service type:             SSH/Terminal
 User group:               system
 Bind attributes:
 Authorization attributes:
  Work directory:          flash:
  User role list:          security-audit

If the HP FlexFabric Switch does not protect audit information from any type of unauthorized read access, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to protect audit information from any type of unauthorized read access. Configure user that has security audit role and privileges:

[HP] local-user security-user
[HP-luser-manage-security-user]  authorization-attribute user-role security-audit
[HP-luser-manage-security-user] password
Password:xxxxxxxxxx
confirm: xxxxxxxxxx
[HP-luser-manage-security-user] service-type ash terminal'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66837r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66191'
  tag rid: 'SV-80681r1_rule'
  tag stig_id: 'HFFS-ND-000036'
  tag gtitle: 'SRG-APP-000118-NDM-000235'
  tag fix_id: 'F-72267r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
