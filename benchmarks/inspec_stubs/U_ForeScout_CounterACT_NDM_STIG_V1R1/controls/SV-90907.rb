control 'SV-90907' do
  title 'CounterACT appliances performing maintenance functions must restrict use of these functions to authorized personal only.'
  desc 'There are security-related issues arising from software brought into the network device specifically for diagnostic and repair actions (e.g., a software packet sniffer installed on a device to troubleshoot system traffic or a vendor installing or running a diagnostic application to troubleshoot an issue with a vendor-supported device). If maintenance tools are used by unauthorized personnel, they may accidentally or intentionally damage or compromise the system.

This requirement addresses security-related issues associated with maintenance tools used specifically for diagnostic and repair actions on organizational network devices. Maintenance tools can include hardware, software, and firmware items. Maintenance tools are potential vehicles for transporting malicious code, either intentionally or unintentionally, into a facility and subsequently into organizational information systems. Maintenance tools can include, for example, hardware/software diagnostic test equipment and hardware/software packet sniffers.

This requirement does not cover hardware/software components that may support information system maintenance yet are a part of the system (e.g., the software implementing "ping," "ls," "ipconfig," or the hardware and software implementing the monitoring port of an Ethernet switch).'
  desc 'check', 'Determine if the network device restricts the use of maintenance functions to authorized personnel only. View the list of users defined on the device.

 Select Tools >> Options >> Console User Profiles.

If other personnel can use maintenance functions on the network device, this is a finding.'
  desc 'fix', 'Configure the access privileges to CounterACT to restrict use of maintenance functions to authorized personnel only.

1. Select Tools >> Options >> Console User Profiles.
2. Adjust or remove the unauthorized group or user profile.

Note: The RAFACS must also be inspected for unauthorized users.'
  impact 0.7
  ref 'DPMS Target ForeScout CounterACT NDM'
  tag check_id: 'C-75905r1_chk'
  tag severity: 'high'
  tag gid: 'V-76219'
  tag rid: 'SV-90907r1_rule'
  tag stig_id: 'CACT-NM-000041'
  tag gtitle: 'SRG-APP-000408-NDM-000314'
  tag fix_id: 'F-82855r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002883']
  tag nist: ['CM-6 b', 'MA-3 (4)']
end
