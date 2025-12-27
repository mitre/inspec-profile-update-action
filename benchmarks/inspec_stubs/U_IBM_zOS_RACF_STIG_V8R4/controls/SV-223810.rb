control 'SV-223810' do
  title 'IBM z/OS SSH daemon must be configured to only use the SSHv2 protocol.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.

To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.'
  desc 'check', 'Locate the SSH daemon configuration file, which may be found in /etc/ssh/ directory.

Alternately:
From UNIX System Services ISPF Shell navigate to ribbon select tools.
Select option 1 - Work with Processes.

If SSH Daemon is not active, this is not a finding.

Examine SSH daemon configuration file. If the variables "Protocol 2,1" or "Protocol 1" are defined on a line without a leading comment, this is a finding.'
  desc 'fix', 'Edit the sshd_config file and set the "Protocol" setting to "2".'
  impact 0.7
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25483r515118_chk'
  tag severity: 'high'
  tag gid: 'V-223810'
  tag rid: 'SV-223810r604139_rule'
  tag stig_id: 'RACF-SH-000050'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-25471r515119_fix'
  tag 'documentable'
  tag legacy: ['SV-107431', 'V-98327']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
