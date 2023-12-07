control 'SV-95525' do
  title 'AAA Services must be configured to use secure protocols when connecting to directory services.'
  desc 'Authenticity protection provides protection against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

Application communication sessions are protected utilizing transport encryption protocols, such as TLS. TLS provides a means to authenticate sessions and encrypt application traffic. Session authentication can be single (one-way) or mutual (two-way) in nature. Single authentication authenticates the server for the client, whereas mutual authentication provides a means for both the client and the server to authenticate each other. 

This requirement addresses communications protection at the application session, versus the network packet, and establishes grounds for confidence at both ends of communications sessions in ongoing identities of other parties and in the validity of information transmitted.'
  desc 'check', 'If AAA Services do not connect to a directory services or other identity provider, but instead perform user and device account management as part of their functionality, this is not applicable.

Review the AAA Services configuration when connecting to directory services or another identity provider. Verify the connection is configured to use secure protocols for transport between AAA Services and the directory services using mutual authentication. The use of LDAP over TLS (LDAPS) is the most common method to secure the directory services or user database traffic. Each protocol egressing the local enclave must be implemented in accordance with its PPSM CAL.

If AAA Services do not use secure protocols when connecting to directory services, this is a finding. If the protocols are not implemented in accordance with the PPSM CAL, this is a finding.'
  desc 'fix', 'Configure AAA Services to use secure protocols when connecting to directory services. The use of LDAP over TLS (LDAPS) is the most common method to secure the directory services or user database traffic. However, proprietary or other protocols may be used in some configurations. Each protocol egressing the local enclave must be implemented in accordance with its PPSM CAL.'
  impact 0.7
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80551r4_chk'
  tag severity: 'high'
  tag gid: 'V-80815'
  tag rid: 'SV-95525r1_rule'
  tag stig_id: 'SRG-APP-000142-AAA-000010'
  tag gtitle: 'SRG-APP-000142-AAA-000010'
  tag fix_id: 'F-87669r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
