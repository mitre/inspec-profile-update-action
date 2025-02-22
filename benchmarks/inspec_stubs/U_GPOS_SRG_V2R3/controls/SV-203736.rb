control 'SV-203736' do
  title 'The operating system must implement cryptographic mechanisms to protect the integrity of nonlocal maintenance and diagnostic communications, when used for nonlocal maintenance sessions.'
  desc 'Privileged access contains control and configuration information and is particularly sensitive, so additional protections are necessary. This is maintained by using cryptographic mechanisms, such as a hash function or digital signature, to protect integrity. 

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection. 

The operating system can meet this requirement through leveraging a cryptographic module. This requirement does not cover hardware/software components that may support information system maintenance, yet are a part of the system (e.g., the software implementing "ping," "ls," "ipconfig," or the hardware and software implementing the monitoring port of an Ethernet switch).'
  desc 'check', 'Verify the operating system implements cryptographic mechanisms to protect the integrity of nonlocal maintenance and diagnostic communications, when used for nonlocal maintenance sessions. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to implement cryptographic mechanisms to protect the integrity of nonlocal maintenance and diagnostic communications, when used for nonlocal maintenance sessions.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3861r375272_chk'
  tag severity: 'medium'
  tag gid: 'V-203736'
  tag rid: 'SV-203736r379966_rule'
  tag stig_id: 'SRG-OS-000393-GPOS-00173'
  tag gtitle: 'SRG-OS-000393'
  tag fix_id: 'F-3861r375273_fix'
  tag 'documentable'
  tag legacy: ['V-56793', 'SV-71053']
  tag cci: ['CCI-002890']
  tag nist: ['MA-4 (6)']
end
