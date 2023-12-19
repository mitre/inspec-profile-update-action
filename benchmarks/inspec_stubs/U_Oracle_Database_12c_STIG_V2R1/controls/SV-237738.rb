control 'SV-237738' do
  title 'The DBMS must terminate the network connection associated with a communications session at the end of the session or 15 minutes of inactivity.'
  desc 'Non-local maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network.

The act of managing systems and applications includes the ability to access sensitive application information, such as system configuration details, diagnostic information, user information, and potentially sensitive application data.

When applications provide a remote management capability inherent to the application, the application needs to ensure all sessions and network connections are terminated when non-local maintenance is completed.

When network connections are left open after the database session has closed, the network session is open to session hijacking.

The Oracle Listener inherently meets most of this SRG requirement.  When a user logs off, or times out, or encounters an unrecoverable network fault, the Oracle Listener terminates all sessions and network connections.  The remaining aspect of the requirement, the timeout because of inactivity, is configurable.'
  desc 'check', 'Review DBMS settings, OS settings, and vendor documentation to verify network connections are terminated when a database communications session is ended or after 15 minutes of inactivity.

If the network connection is not terminated, this is a finding.

The defined duration for these timeouts 15 minutes, except to fulfill documented and validated mission requirements.'
  desc 'fix', 'Configure DBMS and/or OS settings to disconnect network sessions when database communication sessions have ended or after the DoD-defined period of inactivity.

To configure this in Oracle, modify each relevant profile.  The resource name is IDLE_TIME, which is expressed in minutes.  Using PPPPPP as an example of a profile, set the timeout to 15 minutes with:
ALTER PROFILE PPPPPP LIMIT IDLE_TIME 15;'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-40957r667244_chk'
  tag severity: 'medium'
  tag gid: 'V-237738'
  tag rid: 'SV-237738r667246_rule'
  tag stig_id: 'O121-C2-016500'
  tag gtitle: 'SRG-APP-000295-DB-000305'
  tag fix_id: 'F-40920r667245_fix'
  tag 'documentable'
  tag legacy: ['V-61757', 'SV-76247']
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
