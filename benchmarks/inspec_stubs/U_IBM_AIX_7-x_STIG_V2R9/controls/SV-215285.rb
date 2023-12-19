control 'SV-215285' do
  title 'AIX must monitor and record successful remote logins.'
  desc 'Remote access services, such as those providing remote access to network devices and information systems, which lack automated monitoring capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Automated monitoring of remote access sessions allows organizations to detect cyber attacks and also ensure ongoing compliance with remote access policies by auditing connection activities of remote access capabilities, such as Remote Desktop Protocol (RDP), on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).'
  desc 'check', 'Check if the file "/var/adm/wtmp" is a symlink by using the following command:
# ls -al /var/adm/wtmp 

The above command should yield the following output: 
-rw-rw-r--    1 adm      adm           45360 Sep 05 15:00 /var/adm/wtmp

If the file "/var/adm/wtmp" is a symlink, this is a finding.'
  desc 'fix', 'Remove the symlink of "/var/adm/wtmp" file by using the following command:
# rm /var/adm/wtmp

The "/var/adm/wtmp" file will be created when the system logs event for successful or failed login.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16483r294306_chk'
  tag severity: 'medium'
  tag gid: 'V-215285'
  tag rid: 'SV-215285r508663_rule'
  tag stig_id: 'AIX7-00-002100'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-16481r294307_fix'
  tag 'documentable'
  tag legacy: ['V-91239', 'SV-101339']
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
