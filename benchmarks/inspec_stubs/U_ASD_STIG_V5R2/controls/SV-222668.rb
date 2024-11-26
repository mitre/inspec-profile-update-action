control 'SV-222668' do
  title 'The system must alert an administrator when low resource conditions are encountered.'
  desc 'In order to prevent DoS type attacks, applications should be monitored when resource conditions reach a predefined threshold. This could indicate the onset of a DoS attack or could be the precursor to an application outage.'
  desc 'check', 'Review the system documentation and interview the application and system administrators.

Examine the system to determine if an automated, continuous on-line monitoring and audit trail creation capability is present with the capability to immediately alert personnel of any unusual or inappropriate activity with potential IA implications, and with a user configurable capability to automatically disable the system if serious IA violations are detected.

If this monitoring capability does not exist, this is a finding.'
  desc 'fix', 'Implement mechanisms to alert system administrators about a low resource condition.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24338r493912_chk'
  tag severity: 'medium'
  tag gid: 'V-222668'
  tag rid: 'SV-222668r864450_rule'
  tag stig_id: 'APSC-DV-003330'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24327r493913_fix'
  tag 'documentable'
  tag legacy: ['SV-85037', 'V-70415']
  tag cci: ['CCI-001274']
  tag nist: ['SI-4 (12)']
end
