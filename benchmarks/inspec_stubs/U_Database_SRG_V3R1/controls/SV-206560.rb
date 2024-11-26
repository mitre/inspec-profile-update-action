control 'SV-206560' do
  title 'The DBMS must map the PKI-authenticated identity to an associated user account.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates. Once a PKI certificate has been validated, it must be mapped to a DBMS user account for the authenticated identity to be meaningful to the DBMS and useful for authorization decisions.'
  desc 'check', 'Review DBMS configuration to verify DBMS user accounts are being mapped directly to unique identifying information within the validated PKI certificate.

If user accounts are not being mapped to authenticated identities, this is a finding.'
  desc 'fix', 'Configure the DBMS to map the authenticated identity directly to the DBMS user account.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6820r291348_chk'
  tag severity: 'medium'
  tag gid: 'V-206560'
  tag rid: 'SV-206560r617447_rule'
  tag stig_id: 'SRG-APP-000177-DB-000069'
  tag gtitle: 'SRG-APP-000177'
  tag fix_id: 'F-6820r291349_fix'
  tag 'documentable'
  tag legacy: ['SV-42815', 'V-32478']
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
