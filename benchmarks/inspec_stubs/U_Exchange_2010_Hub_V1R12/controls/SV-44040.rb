control 'SV-44040' do
  title 'Email software must be monitored for change on INFOCON frequency schedule.'
  desc 'The INFOCON system provides a framework within which the Commander USSTRATCOM regional commanders, service chiefs, base/post/camp/station/vessel commanders, or agency directors can increase the measurable readiness of their networks to match operational priorities. The readiness strategy provides the ability to continuously maintain and sustain one’s own information systems and networks throughout their schedule of deployments, exercises, and operational readiness life cycle independent of network attacks or threats. The system provides a framework of prescribed actions and cycles necessary for reestablishing the confidence level and security of information systems for the commander and thereby supporting the entire Global Information Grid (GIG) (SD 527-1 Purpose).

The Exchange software files and directories are vulnerable to unauthorized changes if not adequately protected.  An unauthorized change could affect the integrity or availability of email services overall. For this reason, all application software installations must monitor for change against a software baseline that is preserved when installed, and updated periodically as patches or upgrades are installed. Automated and manual schedules for software change monitoring must be compliant with SD527-1 frequencies. 

Note: Policy Auditor 5.2 or later, File Integrity Monitor (FIM) module will meet the requirement for file integrity checking. The Asset module within HBSS does not meet this requirement.'
  desc 'check', 'Access the EDSP baseline section and determine the process and frequency for identifying software changes (*.exe, *.bat, *.com, *.cmd, and *.dll) on servers against a baseline.  

Examine artifacts identified as outputs of this process.  

If baseline comparisons are not done on the INFOCON-required schedule, this is a finding.'
  desc 'fix', 'Implement a process to compare software against a baseline (*.exe, *.bat, *.com, *.cmd, and *.dll) on a frequency required by the prevailing INFOCON level. 

 Document the process and output artifacts in the EDSP.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41727r1_chk'
  tag severity: 'medium'
  tag gid: 'V-33620'
  tag rid: 'SV-44040r1_rule'
  tag stig_id: 'Exch-3-003'
  tag gtitle: 'Exch-3-003'
  tag fix_id: 'F-37512r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
