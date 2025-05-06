control 'SV-29995' do
  title 'The ESCON Director Application Console Event log must be enabled.'
  desc 'The ESCON Director Console Event Log is used to record all ESCON Director Changes. Failure to create an ESCON Director Application Console Event log results in the lack of monitoring and accountability of configuration changes. In addition, its use in the execution of a contingency plan could be compromised and security degraded.  NOTE: Many newer installations no longer support the ESCON Director Console.  For installations not supporting the ESCON Director Console, this check is not applicable.'
  desc 'check', 'If the ESCON Director Console is present, verify on the ESCON Director Application Console that the Event log is in use, otherwise this check is not applicable.

If no Event log exists, this is a finding.'
  desc 'fix', 'Ensure that an ESCON Director Application Console log is created and in use every time the system is switched on.

The ESCON Director maintains an audit trail at the ESCD console’s fixed disk. This audit trail logs the time, date, and password identification when changes have been made to the ESCON Director.'
  impact 0.7
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-2770r4_chk'
  tag severity: 'high'
  tag gid: 'V-24343'
  tag rid: 'SV-29995r3_rule'
  tag stig_id: 'HLESC030'
  tag gtitle: 'HLESC030'
  tag fix_id: 'F-2356r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Systems Programmer']
  tag ia_controls: 'ECAT-1, ECAT-2'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
