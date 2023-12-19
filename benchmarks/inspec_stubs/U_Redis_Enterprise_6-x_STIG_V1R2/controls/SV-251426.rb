control 'SV-251426' do
  title 'Redis Enterprise DBMS must generate audit records for DoD-defined auditable events within all DBMS/database components.'
  desc 'Redis Enterprise does not generate all the DoD-required audit records.

This could lead to incomplete information as follows:
- Without an audit trail, unauthorized access to protected data and attempts to elevate or restrict privileges could go undetected. 
- It would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
- Without the creation of certain audit logs, it would be difficult to identify attempted attacks, and an audit trail would not be available for some forensic investigation for after-the-fact actions. 

For a complete list of unsupported audit requirements, email "disa.letterkenny.re.mbx.stig-customer-support-mailbox@mail.mil". Once the identity of the requester has been verified and the specifics of missing audit requirements obtained, risk can be assessed and a determination made as to whether it is acceptable.'
  desc 'check', 'This requirement is a permanent finding and cannot be fixed. Redis Enterprise does not currently support session or transactional auditing on the database. 

Redis Enterprise does not generate all the DoD-required audit records; therefore this is a finding.

The site must seek AO or ISSO approval for use of Redis Enterprise 6.x with the understanding that not all of the DoD audit requirements are being met.'
  desc 'fix', 'This requirement is a permanent finding and cannot be fixed.

This audit requirement must be continuously monitored.

It must be marked as an "open" finding to serve as a reminder to the AO and other stakeholders that this is an approved risk and needs to be reviewed periodically.'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54859r808341_chk'
  tag severity: 'medium'
  tag gid: 'V-251426'
  tag rid: 'SV-251426r808342_rule'
  tag stig_id: 'RD6X-00-012600'
  tag gtitle: 'SRG-APP-000089-DB-000064'
  tag fix_id: 'F-54814r806432_fix'
  tag 'documentable'
  tag legacy: ['SV-42699', 'V-32362']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
