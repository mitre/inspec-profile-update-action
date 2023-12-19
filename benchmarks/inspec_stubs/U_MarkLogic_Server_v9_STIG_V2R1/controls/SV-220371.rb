control 'SV-220371' do
  title 'MarkLogic Server must maintain the authenticity of communications sessions by guarding against man-in-the-middle attacks that guess at Session ID values.'
  desc 'One class of man-in-the-middle, or session hijacking, attacks involves the adversary guessing at valid session identifiers based on patterns in known identifiers.

The preferred technique for thwarting guesses at Session IDs is the generation of unique session identifiers using a FIPS 140-2 or 140-3 approved random number generator.

However, it is recognized that available DBMS products do not all implement the preferred technique yet may have other protections against session hijacking. Therefore, other techniques are acceptable, provided they are demonstrated to be effective.

MarkLogic Server uses OpenSSL to implement the Secure Sockets Layer (SSL v3) and Transport Layer Security (TLS v1) protocols.'
  desc 'check', 'Review MarkLogic settings to determine whether protections against man-in-the-middle attacks that guess at session identifier values are enabled.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the App Server to check resides (e.g., Default).
3. Click the App Servers icon on the left tree menu.
4. If any of the application servers has a "no" under the SSL column, this is a finding.'
  desc 'fix', 'Configure MarkLogic settings to enable protections against man-in-the-middle attacks that guess at session identifier values.

Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.
See: https://docs.marklogic.com/guide/security/SSL

1. Click the Groups icon.
2. Click the group in which the App Server to check resides (e.g., Default).
3. Click the App Servers icon on the left tree menu.
4. For each of the app servers that has a "no" under the SSL column, follow the instructions outlined in MarkLogic Server - Security Guide Rev 9-0.9, Chapter 9.0: Configuring SSL on App Servers.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22086r401564_chk'
  tag severity: 'medium'
  tag gid: 'V-220371'
  tag rid: 'SV-220371r863305_rule'
  tag stig_id: 'ML09-00-004800'
  tag gtitle: 'SRG-APP-000224-DB-000384'
  tag fix_id: 'F-22075r401565_fix'
  tag 'documentable'
  tag legacy: ['SV-110091', 'V-100987']
  tag cci: ['CCI-001188']
  tag nist: ['SC-23 (3)']
end
