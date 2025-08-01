control 'SV-224387' do
  title 'The BlackBerry UEM server Blackberry Web Services must not be authorized access from external sources unnecessarily.'
  desc 'By limiting access to the subset of Administrator UI functions to internal administrators, the risk of an attacker developing a custom application to administer UEM potentially changing pre-configuration items in UEM is reduced

SFR ID: FMT_SMF.1.1(2) b / CM-7 b

'
  desc 'check', 'Verify BlackBerry UEM server Blackberry Web Services has not been configured to allow access from external sources unnecessarily.

1. Log in to the UEM Server console.
2. On the left bar, access Settings >> General Settings >> Blackberry Web Services access.
3. Verify the status has not changed from disabled unless the ISSM has approved access. 

If BlackBerry UEM server Blackberry Web Services has not disabled access from external sources unnecessarily without ISSM approval, this is a finding.'
  desc 'fix', 'Configure BlackBerry UEM server Blackberry Web Services to block access by unnecessary to external sources (default configuration).

1. Access the UEM Server console.
2. On the left bar, access Settings >> General Settings >> Blackberry Web Services access.
3. If the status is not set to "disabled", change the status to "disabled" unless access has been approved by the ISSM.'
  impact 0.5
  ref 'DPMS Target BlackBerry UEM'
  tag check_id: 'C-26064r539061_chk'
  tag severity: 'medium'
  tag gid: 'V-224387'
  tag rid: 'SV-224387r604136_rule'
  tag stig_id: 'BUEM-00-200280'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-26052r539062_fix'
  tag satisfies: ['SRG-APP-000142']
  tag 'documentable'
  tag legacy: ['SV-111891', 'V-102929']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
