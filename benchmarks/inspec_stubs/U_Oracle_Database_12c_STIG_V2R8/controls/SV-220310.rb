control 'SV-220310' do
  title 'The DBMS must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  desc 'To assure accountability and prevent unauthorized access, organizational users shall be identified and authenticated.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors, guest researchers, individuals from allied nations).

Users (and any processes acting on behalf of users) are uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization which outlines specific user actions that can be performed on the information system without identification or authentication.'
  desc 'check', 'Review DBMS settings, OS settings, and/or enterprise-level authentication/access mechanism settings, and site practices, to determine whether organizational users are uniquely identified and authenticated when logging on to the system.

If organizational users are not uniquely identified and authenticated, this is a finding.'
  desc 'fix', 'Configure DBMS, OS and/or enterprise-level authentication/access mechanism to uniquely identify and authenticate all organizational users who log on to the system.  Ensure that each user has a separate account from all other users.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-22025r392061_chk'
  tag severity: 'medium'
  tag gid: 'V-220310'
  tag rid: 'SV-220310r879589_rule'
  tag stig_id: 'O121-P2-012800'
  tag gtitle: 'SRG-APP-000148-DB-000103'
  tag fix_id: 'F-22017r392062_fix'
  tag 'documentable'
  tag legacy: ['SV-76369', 'V-61879']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
