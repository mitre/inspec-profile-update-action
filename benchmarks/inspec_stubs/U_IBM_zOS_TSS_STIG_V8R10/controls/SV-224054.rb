control 'SV-224054' do
  title 'IBM z/OS SMF recording options for the SSH daemon must be configured to write SMF records for all eligible events.'
  desc 'SMF data collection is the basic unit of tracking of all system functions and actions. Included in this tracking data are the audit trails from each of the ACPs. If the control options for the recording of this tracking are not properly maintained, then accountability cannot be monitored, and its use in the execution of a contingency plan could be compromised.

'
  desc 'check', 'Locate the SSH daemon configuration file, which may be found in /etc/ssh/ directory.

Alternately:
From UNIX System Services ISPF Shell, navigate to ribbon select tools.
Select option 1 - Work with Processes.

If SSH Daemon is not active, this is not a finding.

Examine SSH daemon configuration file. 

If ServerSMF is not coded with ServerSMF TYPE119_U83 or is commented out, this is a finding.'
  desc 'fix', 'Configure the SERVERSMF statement in the SSH Daemon configuration file to TYPE119_U83.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25727r904398_chk'
  tag severity: 'medium'
  tag gid: 'V-224054'
  tag rid: 'SV-224054r904400_rule'
  tag stig_id: 'TSS0-SS-000010'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-25715r904399_fix'
  tag satisfies: ['SRG-OS-000032-GPOS-00013', 'SRG-OS-000392-GPOS-00172']
  tag 'documentable'
  tag legacy: ['SV-107919', 'V-98815']
  tag cci: ['CCI-000067', 'CCI-002884']
  tag nist: ['AC-17 (1)', 'MA-4 (1) (a)']
end
