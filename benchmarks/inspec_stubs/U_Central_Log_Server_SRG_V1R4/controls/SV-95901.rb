control 'SV-95901' do
  title 'For devices and hosts within the scope of coverage, the Central Log Server must be configured to automatically aggregate events that indicate account actions.'
  desc 'If the Central Log Server is configured to filter or remove account log records transmitted by devices and hosts within its scope of coverage, forensic analysis tools will be less effective at detecting and reporting on important attack vectors. A comprehensive account management process must include capturing log records for the creation of user accounts and notification of administrators and/or application owners. Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes. 

This requirement addresses the concern that the Central Log Server may be configured to filter out certain levels of information, which may result in the discarding of DoD-required accounting actions addressed in the AC-2 (4) controls such as creation, modification, deletion, and removal of privileged accounts.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server automatically aggregates events that indicate account actions for each device and host within its scope of coverage.

If the Central Log Server is not configured to automatically aggregate events that indicate account actions for each device and host within its scope of coverage, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to automatically aggregate events that indicate account actions for each device and host within its scope of coverage.'
  impact 0.5
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-80853r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81187'
  tag rid: 'SV-95901r1_rule'
  tag stig_id: 'SRG-APP-000516-AU-000370'
  tag gtitle: 'SRG-APP-000516-AU-000370'
  tag fix_id: 'F-87963r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
