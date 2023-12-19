control 'SV-80395' do
  title 'Trend Deep Security must scan all media used for system maintenance prior to use.'
  desc 'There are security-related issues arising from software brought into the information system specifically for diagnostic and repair actions (e.g., a software packet sniffer installed on a system in order to troubleshoot system traffic, or a vendor installing or running a diagnostic application in order to troubleshoot an issue with a vendor supported system).

If, upon inspection of media containing maintenance diagnostic and test programs, organizations determine that the media contain malicious code, the incident is handled consistent with organizational incident handling policies and procedures.

This requirement addresses security-related issues associated with maintenance tools used specifically for diagnostic and repair actions on organizational information systems. Maintenance tools can include hardware, software, and firmware items. Maintenance tools are potential vehicles for transporting malicious code, either intentionally or unintentionally, into a facility and subsequently into organizational information systems. Maintenance tools can include, for example, hardware/software diagnostic test equipment and hardware/software packet sniffers. This requirement does not cover hardware/software components that may support information system maintenance, yet are a part of the system (e.g., the software implementing "ping," "ls," "ipconfig," or the hardware and software implementing the monitoring port of an Ethernet switch).'
  desc 'check', 'Review the Trend Deep Security server to ensure all media used for system maintenance is scanned prior to use.

Verify Anti-Malware is enabled on each server that is applicable to the accreditation boundary.

Go to Computers.
Right-click a computer from the list of systems, select properties Anti-Malware >> General
Verify Configuration is set to "On" or "Inherit On".

If Verify Configuration is set to "Off", this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to scan all media used for system maintenance prior to use.

The scope of Malware Scans can be controlled by editing the Malware Scan Configuration that is in effect on a computer. The Malware Scan Configuration determines which files and directories are included or excluded during a scan and which actions are taken if malware is detected on a computer (for example, clean, quarantine, or delete). There are two types of Malware Scan Configurations:
- Manual/Scheduled Scan Configurations
- Real-Time Scan Configurations

To enable Anti-Malware functionality on a computer:
Go to Computers.
Right-click a computer from the list of systems, select properties Anti-Malware >> General
Set Configuration to "On" or "Inherit On".'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66553r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65905'
  tag rid: 'SV-80395r1_rule'
  tag stig_id: 'TMDS-00-000055'
  tag gtitle: 'SRG-APP-000073'
  tag fix_id: 'F-71981r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000870']
  tag nist: ['MA-3 (2)']
end
