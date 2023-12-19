control 'SV-242186' do
  title 'In the event of a logging failure caused by the lack of audit record storage capacity, the SMS must continue generating and storing audit records, overwriting the oldest audit records in a first-in-first-out manner using Audit Log maintenance.'
  desc 'It is critical that when the TPS is at risk of failing to process audit logs as required, it takes action to mitigate the failure.

The IDPS performs a critical security function, so its continued operation is imperative. Since availability of the TPS is an overriding concern, shutting down the system in the event of an audit failure should be avoided, except as a last resort.'
  desc 'check', '1. In the Trend Micro SMS interface, go to the "Admin" tab, and select "Database". Each item in the database maintenance section has a configurable item to ensure when the newest logs will overwrite the oldest logs. This is configured through the number of rows:
   a. The Events log must be set to at least 30,000,000 rows, with an age of 90 days. 
   b. The Audit Log must be set 1,000,000 rows and an age of 365 days. 
   c. The Device Audit Log must be set 1,000,000 rows and an age of 365 days. 
   d. The Device System Log must be set 1,000,000 rows and an age of 365 days. 

If these values are not set, this is a finding.'
  desc 'fix', '1. In the Trend Micro SMS interface, go to the "Admin" tab, and select "Database". 
2. Make the following changes: 
   a. The Events log must be set to at least 30,000,000 rows, with an age of 90 days. 
   b. The Audit Log must be set 1,000,000 rows and an age of 365 days. 
   c. The Device Audit Log must be set 1,000,000 rows and an age of 365 days. 
   d. The Device System Log must be set 1,000,000 rows and an age of 365 days.'
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint IDPS'
  tag check_id: 'C-45461r710099_chk'
  tag severity: 'medium'
  tag gid: 'V-242186'
  tag rid: 'SV-242186r710101_rule'
  tag stig_id: 'TIPP-IP-000200'
  tag gtitle: 'SRG-NET-000089-IDPS-00069'
  tag fix_id: 'F-45419r710100_fix'
  tag 'documentable'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
