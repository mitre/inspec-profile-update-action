control 'SV-254123' do
  title 'Nutanix AOS must monitor remote access methods.'
  desc 'Remote access services, such as those providing remote access to network devices and information systems, which lack automated monitoring capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Automated monitoring of remote access sessions allows organizations to detect cyberattacks and also ensure ongoing compliance with remote access policies by auditing connection activities of remote access capabilities, such as Remote Desktop Protocol (RDP), on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).'
  desc 'check', 'Confirm Nutanix AOS monitors remote access methods.

$ sudo grep -i loglevel /etc/ssh/sshd_config

If the LogLevel is not set to "VERBOSE", this is a finding.'
  desc 'fix', 'Configure SSH to verbosely log connection attempts and failed logon attempts to the operating system by running the following command.

$ sudo salt-call state.sls security/CVM/sshdCVM

The SSH service will need to be restarted for the changes to take effect:

$ sudo systemctl restart sshd'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57608r846455_chk'
  tag severity: 'medium'
  tag gid: 'V-254123'
  tag rid: 'SV-254123r846457_rule'
  tag stig_id: 'NUTX-OS-000060'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-57559r846456_fix'
  tag 'documentable'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
