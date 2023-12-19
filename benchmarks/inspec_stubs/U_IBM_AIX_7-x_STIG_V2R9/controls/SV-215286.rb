control 'SV-215286' do
  title 'AIX must monitor and record unsuccessful remote logins.'
  desc 'Remote access services, such as those providing remote access to network devices and information systems, which lack automated monitoring capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Automated monitoring of remote access sessions allows organizations to detect cyberattacks and also ensure ongoing compliance with remote access policies by auditing connection activities of remote access capabilities, such as Remote Desktop Protocol (RDP), on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).'
  desc 'check', 'Check if the file "/etc/security/failedlogin" is a symlink by using the following command:
# ls -al /etc/security/failedlogin

The above command should yield the following output: 
-rw-------    1 root     system          648 Sep 05 14:59 /etc/security/failedlogin

If the file "/etc/security/failedlogin" is a symlink, this is a finding.'
  desc 'fix', 'Remove the symlink of "/etc/security/failedlogin" file by using the following command:
# rm /etc/security/failedlogin

The "/etc/security/failedlogin" file will be created when system logs event for a failed login.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16484r294309_chk'
  tag severity: 'medium'
  tag gid: 'V-215286'
  tag rid: 'SV-215286r508663_rule'
  tag stig_id: 'AIX7-00-002101'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-16482r294310_fix'
  tag 'documentable'
  tag legacy: ['V-91241', 'SV-101341']
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
