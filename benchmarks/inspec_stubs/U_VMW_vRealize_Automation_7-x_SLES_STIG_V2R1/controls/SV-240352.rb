control 'SV-240352' do
  title 'The SLES for vRealize must monitor remote access methods - SSH Daemon.'
  desc 'Remote access services, such as those providing remote access to network devices and information systems, which lack automated monitoring capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Automated monitoring of remote access sessions allows organizations to detect cyber attacks and also ensure ongoing compliance with remote access policies by auditing connection activities of remote access capabilities, such as Remote Desktop Protocol (RDP), on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).'
  desc 'check', %q(Verify that SSH is configured to verbosely log connection attempts and failed logon attempts to the server by running the following command:

# grep LogLevel /etc/ssh/sshd_config  | grep -v '#' 

The output message must contain the following text:

LogLevel VERBOSE

If it is not set to "VERBOSE", this is a finding.)
  desc 'fix', "To configure SSH to verbosely log connection attempts and failed logon attempts to the server, run the following command:

# sed -i 's/^.*\\bLogLevel\\b.*$/LogLevel VERBOSE/' /etc/ssh/sshd_config

The SSH service will need to be restarted after the above change has been made to SSH. This can be done by running the following command:

# service sshd restart"
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43585r670795_chk'
  tag severity: 'medium'
  tag gid: 'V-240352'
  tag rid: 'SV-240352r670797_rule'
  tag stig_id: 'VRAU-SL-000070'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-43544r670796_fix'
  tag 'documentable'
  tag legacy: ['SV-100131', 'V-89481']
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
