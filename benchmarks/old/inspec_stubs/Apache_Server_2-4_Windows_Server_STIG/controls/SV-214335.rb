control 'SV-214335' do
  title 'The Apache web server must generate unique session identifiers with definable entropy.'
  desc 'Generating a session identifier (ID) that is not easily guessed through brute force is essential to deter several types of session attacks. By knowing the session ID, an attacker can hijack a user session that has already been user authenticated by the hosted application. The attacker does not need to guess user identifiers and passwords or have a secure token since the user session has already been authenticated.

Random and unique session IDs are the opposite of sequentially generated session IDs, which can be easily guessed by an attacker. Random session identifiers help to reduce predictability of said identifiers. The session ID must be unpredictable (random enough) to prevent guessing attacks, where an attacker is able to guess or predict the ID of a valid session through statistical analysis techniques. For this purpose, a good Pseudo Random Number Generator (PRNG) must be used.

Unique session IDs address man-in-the-middle attacks, including session hijacking or insertion of false information into a session. If the attacker is unable to identify or guess the session information related to pending application traffic, they will have more difficulty in hijacking the session or otherwise manipulating valid sessions.

At least half of a session ID must be created using a definable source of entropy (PRNG).'
  desc 'check', %q(Review the <'INSTALLED PATH'>\conf\httpd.conf file.

Verify the "ssl_module" is loaded.

If it does not exist, this is a finding.

If the "SSLRandomSeed" directive is missing or does not look like the following, this is a finding:

SSLRandomSeed startup builtin
SSLRandomSeed connect builtin)
  desc 'fix', %q(Edit the <'INSTALLED PATH'>\conf\httpd.conf file and load the "ssl_module" module.

Set the "SSLRandomSeed" directives to the following:

SSLRandomSeed startup builtin
SSLRandomSeed connect builtin

Restart the Apache service.)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Server'
  tag check_id: 'C-15547r277508_chk'
  tag severity: 'medium'
  tag gid: 'V-214335'
  tag rid: 'SV-214335r879639_rule'
  tag stig_id: 'AS24-W1-000530'
  tag gtitle: 'SRG-APP-000224-WSR-000139'
  tag fix_id: 'F-15545r277509_fix'
  tag 'documentable'
  tag legacy: ['SV-102507', 'V-92419']
  tag cci: ['CCI-001188']
  tag nist: ['SC-23 (3)']
end
