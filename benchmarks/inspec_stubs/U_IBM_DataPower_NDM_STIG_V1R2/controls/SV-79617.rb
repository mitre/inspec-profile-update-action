control 'SV-79617' do
  title 'The DataPower Gateway must automatically audit account enabling actions.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply enable a new or disabled account. Notification of account enabling is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail which documents the creation of application user accounts and notifies administrators and Information System Security Officers (ISSOs). Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.'
  desc 'check', 'View the logging settings: Objects >> Logging Configuration >> Audit Log Settings. Then examine the audit log after enabling or disabling an account (the most recent entry will be at the bottom of the log).

If this message is not present, this is a finding.'
  desc 'fix', 'Configure a comprehensive audit trail by turning on the audit log using the web interface (Objects >> Logging Configuration >> Audit Log Settings) then setting the desired level of logging detail for audit-events.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65755r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65127'
  tag rid: 'SV-79617r1_rule'
  tag stig_id: 'WSDP-NM-000085'
  tag gtitle: 'SRG-APP-000319-NDM-000283'
  tag fix_id: 'F-71067r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002130']
  tag nist: ['AC-2 (4)']
end
