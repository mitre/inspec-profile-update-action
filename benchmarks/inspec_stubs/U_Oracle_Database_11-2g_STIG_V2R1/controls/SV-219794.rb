control 'SV-219794' do
  title 'The DBMS must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  desc 'To assure accountability and prevent unauthorized access, organizational users shall be identified and authenticated. 

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors, guest researchers, individuals from allied nations). 

Users (and any processes acting on behalf of users) are uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization which outlines specific user actions that can be performed on the information system without identification or authentication.'
  desc 'check', 'Review DBMS settings, OS settings, and/or enterprise-level authentication/access mechanism settings, and site practices, to determine whether organizational users are uniquely identified and authenticated when logging onto the system. If organizational users are not uniquely identified and authenticated, this is a finding.'
  desc 'fix', 'Configure DBMS, OS and/or enterprise-level authentication/access mechanism to uniquely identify and authenticate all organizational users who log onto the system.  Ensure that each user has a separate account from all other users.

(This is the default behavior of Oracle.)'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-21519r307231_chk'
  tag severity: 'medium'
  tag gid: 'V-219794'
  tag rid: 'SV-219794r395859_rule'
  tag stig_id: 'O112-P2-012800'
  tag gtitle: 'SRG-APP-000148-DB-000103'
  tag fix_id: 'F-21518r307232_fix'
  tag 'documentable'
  tag legacy: ['SV-66667', 'V-52451']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
