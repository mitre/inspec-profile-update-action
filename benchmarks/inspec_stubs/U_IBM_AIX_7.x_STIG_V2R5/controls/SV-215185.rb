control 'SV-215185' do
  title 'SSH must display the date and time of the last successful account login to AIX system upon login.'
  desc 'Remote access services, such as those providing remote access to network devices and information systems, which lack automated control capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Operating system functionality (e.g., RDP) must be capable of taking enforcement action if the audit reveals unauthorized activity. Automated control of remote access sessions allows organizations to ensure ongoing compliance with remote access policies by enforcing connection rules of remote access applications on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).'
  desc 'check', 'Verify the SSH daemon is configured to display last login information using command: 
# cat /etc/ssh/sshd_config | grep -i ^PrintLastLog 
PrintLastLog yes

If "PrintLastLog" is not set to "yes", this is a finding.'
  desc 'fix', 'Edit the "/etc/ssh/sshd_config" file to add or update the following line:
PrintLastLog yes.

Restart sshd service:
# stopsrc -s sshd
# startsrc -s sshd'
  impact 0.3
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16383r294006_chk'
  tag severity: 'low'
  tag gid: 'V-215185'
  tag rid: 'SV-215185r508663_rule'
  tag stig_id: 'AIX7-00-001024'
  tag gtitle: 'SRG-OS-000297-GPOS-00115'
  tag fix_id: 'F-16381r294007_fix'
  tag 'documentable'
  tag legacy: ['V-91501', 'SV-101599']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
