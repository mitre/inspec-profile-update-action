control 'SV-234815' do
  title 'The SUSE operating system must log SSH connection attempts and failures to the server.'
  desc 'Remote access services, such as those providing remote access to network devices and information systems, which lack automated monitoring capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Automated monitoring of remote access sessions allows organizations to detect cyber attacks and also ensure ongoing compliance with remote access policies by auditing connection activities of remote access capabilities, such as Remote Desktop Protocol (RDP), on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).'
  desc 'check', 'Verify SSH is configured to verbosely log connection attempts and failed logon attempts to the SUSE operating system.

Check that the SSH daemon configuration verbosely logs connection attempts and failed logon attempts to the server with the following command:

> sudo grep -i loglevel /etc/ssh/sshd_config

The output message must contain the following text:

LogLevel VERBOSE

If the output message does not contain "VERBOSE", the LogLevel keyword is missing, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure SSH to verbosely log connection attempts and failed logon attempts to the SUSE operating system.

Add or update the following line in the "/etc/ssh/sshd_config" file:

LogLevel VERBOSE

The SSH service will need to be restarted in order for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38003r618714_chk'
  tag severity: 'medium'
  tag gid: 'V-234815'
  tag rid: 'SV-234815r622137_rule'
  tag stig_id: 'SLES-15-010150'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-37966r618715_fix'
  tag 'documentable'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
