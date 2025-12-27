control 'SV-69057' do
  title 'Signature generation using the KSK must be done off-line, using the KSK-private stored off-line.'
  desc 'Security-relevant information is any information within information systems that can potentially impact the operation of security functions or the provision of security services in a manner that could result in failure to enforce system security policies or maintain the isolation of code and data. 

Security-relevant information includes, for example, file permissions, cryptographic key management information, configuration parameters for security services, and access control lists. Secure, non-operable system states include the times in which information systems are not performing mission/business-related processing (e.g., the system is off-line for maintenance, troubleshooting, boot-up, and shut down).'
  desc 'check', 'Verify the DNS operational procedures and confirm procedures exist to enforce generating signatures using the KSK are performed off-line, using the KSK-private stored off-line or the secure, protected module.

If the procedures do not exist or the procedures do not specify to perform the signature generation off-line from the name server, this is a finding.'
  desc 'fix', 'Create operation documentation to include the safe management of keys and key storage within the DNS implementation. Include in the documentation steps to ensure signature generation using the KSK are done off-line, using the KSK-private stored off-line or the secure, protected module.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55433r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54811'
  tag rid: 'SV-69057r1_rule'
  tag stig_id: 'SRG-APP-000176-DNS-000096'
  tag gtitle: 'SRG-APP-000176-DNS-000096'
  tag fix_id: 'F-59669r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
