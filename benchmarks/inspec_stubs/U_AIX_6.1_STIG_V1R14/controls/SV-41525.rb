control 'SV-41525' do
  title 'The system must not have a public Instant Messaging (IM) client installed.'
  desc 'Public Instant Messaging (IM) systems are not approved for use and may result in the unauthorized distribution of information. IM clients provide a way for a user to send a message to one or more other users in real time. Additional capabilities may include file transfer and support for distributed game playing. Communication between clients and associated directory services are managed through messaging servers. Commercial IM clients include AOL Instant Messenger (AIM), MSN Messenger, and Yahoo! Messenger.

IM clients present a security issue when the clients route messages through public servers. The obvious implication is potentially sensitive information could be intercepted or altered in the course of transmission. This same issue is associated with the use of public email servers. In order to reduce the potential for disclosure of sensitive Government information and to ensure the validity of official government information, IM clients connecting to public IM services will not be installed. Clients used to access internal or DoD-controlled IM services are permitted.'
  desc 'check', 'If an IM client is installed, ask the SA if it has access to any public domain IM servers.  If it does have access to public servers, this is a finding.'
  desc 'fix', 'Uninstall the IM client from the system, or configure the client to only connect to DoD-approved IM services.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-7989r2_chk'
  tag severity: 'medium'
  tag gid: 'V-12024'
  tag rid: 'SV-41525r1_rule'
  tag stig_id: 'GEN006000'
  tag gtitle: 'GEN006000'
  tag fix_id: 'F-11283r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECIM-1'
  tag cci: ['CCI-000366', 'CCI-001154']
  tag nist: ['CM-6 b', 'SC-15 (2)']
end
