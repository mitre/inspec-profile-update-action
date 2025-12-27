control 'SV-205456' do
  title 'Mainframe Products scanning for malicious code must scan all media used for system maintenance prior to use.'
  desc 'There are security-related issues arising from software brought into the information system specifically for diagnostic and repair actions (e.g., a software packet sniffer installed on a system in order to troubleshoot system traffic, or a vendor installing or running a diagnostic application in order to troubleshoot an issue with a vendor-supported system). 

If, upon inspection of media containing maintenance diagnostic and test programs, organizations determine that the media contain malicious code, the incident is handled consistent with organizational incident handling policies and procedures.

This requirement addresses security-related issues associated with maintenance tools used specifically for diagnostic and repair actions on organizational information systems. Maintenance tools can include hardware, software, and firmware items. Maintenance tools are potential vehicles for transporting malicious code, either intentionally or unintentionally, into a facility and subsequently into organizational information systems. Maintenance tools can include, for example, hardware/software diagnostic test equipment and hardware/software packet sniffers. This requirement does not cover hardware/software components that may support information system maintenance, yet are a part of the system (e.g., the software implementing "ping," "ls," "ipconfig," or the hardware and software implementing the monitoring port of an Ethernet switch).'
  desc 'check', 'If the Mainframe Product has no function or capability for scanning activity, this is not applicable.

Examine installation and configuration settings.

If the Mainframe Product is not configured to scan all media brought into the organization for diagnostic and testing purposes for intentional or unintentionally included malicious code prior to use, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to scan all media used in maintenance prior to use.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5722r299601_chk'
  tag severity: 'medium'
  tag gid: 'V-205456'
  tag rid: 'SV-205456r395619_rule'
  tag stig_id: 'SRG-APP-000073-MFP-000255'
  tag gtitle: 'SRG-APP-000073'
  tag fix_id: 'F-5722r299602_fix'
  tag 'documentable'
  tag legacy: ['SV-82909', 'V-68419']
  tag cci: ['CCI-000870']
  tag nist: ['MA-3 (2)']
end
