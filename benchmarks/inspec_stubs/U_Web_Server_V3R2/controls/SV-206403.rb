control 'SV-206403' do
  title 'The web server must generate unique session identifiers with definable entropy.'
  desc 'Generating a session identifier (ID) that is not easily guessed through brute force is essential to deter several types of session attacks. By knowing the session ID, an attacker can hijack a user session that has already been user authenticated by the hosted application. The attacker does not need to guess user identifiers and passwords or have a secure token since the user session has already been authenticated.

Random and unique session IDs are the opposite of sequentially generated session IDs, which can be easily guessed by an attacker. Random session identifiers help to reduce predictability of said identifiers. The session ID must be unpredictable (random enough) to prevent guessing attacks, where an attacker is able to guess or predict the ID of a valid session through statistical analysis techniques. For this purpose, a good PRNG (Pseudo Random Number Generator) must be used.

Unique session IDs address man-in-the-middle attacks, including session hijacking or insertion of false information into a session. If the attacker is unable to identify or guess the session information related to pending application traffic, they will have more difficulty in hijacking the session or otherwise manipulating valid sessions.

At least half of a session ID must be created using a definable source of entropy (PRNG).'
  desc 'check', 'Review the web server documentation and deployed configuration to verify that the web server is generating random session IDs with entropy equal to at least half the session ID length.

If the web server is not configured to generate random session IDs with the proper amount of entropy, this is a finding.'
  desc 'fix', 'Configure the web server to generate random session IDs with minimum entropy equal to half the session ID length.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6664r377801_chk'
  tag severity: 'medium'
  tag gid: 'V-206403'
  tag rid: 'SV-206403r879639_rule'
  tag stig_id: 'SRG-APP-000224-WSR-000139'
  tag gtitle: 'SRG-APP-000224'
  tag fix_id: 'F-6664r377802_fix'
  tag 'documentable'
  tag legacy: ['SV-54387', 'V-41810']
  tag cci: ['CCI-001188']
  tag nist: ['SC-23 (3)']
end
