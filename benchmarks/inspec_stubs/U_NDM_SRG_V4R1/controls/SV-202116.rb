control 'SV-202116' do
  title 'Network devices performing maintenance functions must restrict use of these functions to authorized personnel only.'
  desc 'There are security-related issues arising from software brought into the network device specifically for diagnostic and repair actions (e.g., a software packet sniffer installed on a device in order to troubleshoot system traffic, or a vendor installing or running a diagnostic application in order to troubleshoot an issue with a vendor-supported device). If maintenance tools are used by unauthorized personnel, they may accidentally or intentionally damage or compromise the system.

This requirement addresses security-related issues associated with maintenance tools used specifically for diagnostic and repair actions on organizational network devices. Maintenance tools can include hardware, software, and firmware items. Maintenance tools are potential vehicles for transporting malicious code, either intentionally or unintentionally, into a facility and subsequently into organizational information systems. Maintenance tools can include, for example, hardware/software diagnostic test equipment and hardware/software packet sniffers. This requirement does not cover hardware/software components that may support information system maintenance yet are a part of the system (e.g., the software implementing "ping," "ls," "ipconfig," or the hardware and software implementing the monitoring port of an Ethernet switch).'
  desc 'check', 'Determine if the network device restricts the use of maintenance functions to authorized personnel only.

If other personnel can use maintenance functions on the network device, this is a finding.'
  desc 'fix', 'Configure the network device to restrict use of maintenance functions to authorized personnel only.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2242r382028_chk'
  tag severity: 'medium'
  tag gid: 'V-202116'
  tag rid: 'SV-202116r400147_rule'
  tag stig_id: 'SRG-APP-000408-NDM-000314'
  tag gtitle: 'SRG-APP-000408'
  tag fix_id: 'F-2243r382029_fix'
  tag 'documentable'
  tag legacy: ['SV-69509', 'V-55263']
  tag cci: ['CCI-002883', 'CCI-000366']
  tag nist: ['MA-3 (4)', 'CM-6 b']
end
