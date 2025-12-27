control 'SV-206566' do
  title 'The DBMS must recognize only system-generated session identifiers.'
  desc 'DBMSs utilize sessions and session identifiers to control application behavior and user access. If an attacker can guess the session identifier or can inject or manually insert session information, the session may be compromised.

This requirement focuses on communications protection for the DBMS session rather than for the network packet. The intent of this control is to establish grounds for confidence at each end of a communications session in the ongoing identity of the other party and in the validity of the information being transmitted. 

The DBMS must recognize only system-generated session identifiers. If an attacker were able to generate a session with a non-system-generated session identifier and have it recognized by the system, the attacker could gain access to the system without passing through access controls designed to limit database sessions to authorized users.'
  desc 'check', 'Review DBMS settings and vendor documentation to determine whether the DBMS recognizes session identifiers that are not system-generated.

If the DBMS recognizes session identifiers that are not system generated, this is a finding.'
  desc 'fix', 'Utilize a DBMS product that only recognizes session identifiers that are system-generated.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6826r291366_chk'
  tag severity: 'medium'
  tag gid: 'V-206566'
  tag rid: 'SV-206566r617447_rule'
  tag stig_id: 'SRG-APP-000223-DB-000168'
  tag gtitle: 'SRG-APP-000223'
  tag fix_id: 'F-6826r291367_fix'
  tag 'documentable'
  tag legacy: ['SV-42863', 'V-32526']
  tag cci: ['CCI-001664']
  tag nist: ['SC-23 (3)']
end
