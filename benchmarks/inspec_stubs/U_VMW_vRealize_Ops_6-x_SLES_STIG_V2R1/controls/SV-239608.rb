control 'SV-239608' do
  title 'The SLES for vRealize must audit all activities performed during nonlocal maintenance and diagnostic sessions.'
  desc 'If events associated with nonlocal administrative access or diagnostic sessions are not logged, a major tool for assessing and investigating attacks would not be available.

This requirement addresses auditing-related issues associated with maintenance tools used specifically for diagnostic and repair actions on organizational information systems.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection.

This requirement applies to hardware/software diagnostic test equipment or tools. This requirement does not cover hardware/software components that may support information system maintenance, yet are a part of the system, for example, the software implementing "ping," "ls," "ipconfig," or the hardware and software implementing the monitoring port of an Ethernet switch.'
  desc 'check', 'Verify that all commands run by "root" are being audited with the following command:

# cat /etc/audit/audit.rules | grep execve

If the following lines are not displayed, this is a finding.

-a exit,always -F arch=b64 -F euid=0 -S execve
-a exit,always -F arch=b32 -F euid=0 -S execve'
  desc 'fix', 'Configure SLES for vRealize to log all commands run by "root" with the following command:

# echo "-a exit,always -F arch=b64 -F euid=0 -S execve" >> /etc/audit/audit.rules

# echo "-a exit,always -F arch=b32 -F euid=0 -S execve" >> /etc/audit/audit.rules

Restart the audit service: 

# service auditd restart'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42841r662273_chk'
  tag severity: 'medium'
  tag gid: 'V-239608'
  tag rid: 'SV-239608r662275_rule'
  tag stig_id: 'VROM-SL-001220'
  tag gtitle: 'SRG-OS-000392-GPOS-00172'
  tag fix_id: 'F-42800r662274_fix'
  tag 'documentable'
  tag legacy: ['SV-99337', 'V-88687']
  tag cci: ['CCI-002884']
  tag nist: ['MA-4 (1) (a)']
end
