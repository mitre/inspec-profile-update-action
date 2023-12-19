control 'SV-223806' do
  title 'IBM z/OS SMF recording options for the SSH daemon must be configured to write SMF records for all eligible events.'
  desc 'SMF data collection is the basic unit of tracking of all system functions and actions. Included in this tracking data are the audit trails from each of the ACPs. If the control options for the recording of this tracking are not properly maintained, then accountability cannot be monitored, and its use in the execution of a contingency plan could be compromised.

'
  desc 'check', 'Locate the SSH daemon configuration file, which may be found in /etc/ssh/ directory.

Alternately:
From UNIX System Services ISPF Shell navigate to ribbon select tools.
Select option 1 - Work with Processes.

If SSH Daemon is not active, this is not a finding.

Examine SSH daemon configuration file. 

If ServerSMF is not coded with ServerSMF TYPE119_U83 or is commented out, this is a finding.'
  desc 'fix', 'Configure the SERVERSMF statement in the SSH Daemon configuration file to TYPE119_U83.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25479r515106_chk'
  tag severity: 'medium'
  tag gid: 'V-223806'
  tag rid: 'SV-223806r604139_rule'
  tag stig_id: 'RACF-SH-000010'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-25467r515107_fix'
  tag satisfies: ['SRG-OS-000032-GPOS-00013', 'SRG-OS-000392-GPOS-00172']
  tag 'documentable'
  tag legacy: ['V-98319', 'SV-107423']
  tag cci: ['CCI-000067', 'CCI-002884']
  tag nist: ['AC-17 (1)', 'MA-4 (1) (a)']
end
