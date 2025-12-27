control 'SV-233106' do
  title 'The container platform must employ strong authenticators in the establishment of non-local maintenance and diagnostic sessions.'
  desc 'If maintenance tools are used by unauthorized personnel, they may accidentally or intentionally damage or compromise the system. The act of managing systems and applications includes the ability to access sensitive application information, such as, system configuration details, diagnostic information, user information, and potentially sensitive application data.

Non-local maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection. Typically, strong authentication requires authenticators that are resistant to replay attacks and employ multifactor authentication. Strong authenticators include, for example, PKI where certificates are stored on a token protected by a password, passphrase, or biometric.

This requirement applies to hardware/software diagnostic test equipment or tools. This requirement does not cover hardware/software components that may support information system maintenance, yet are a part of the system (e.g., the software implementing "ping," "ls," "ipconfig," or the hardware and software implementing the monitoring port of an Ethernet switch).'
  desc 'check', 'Review the container platform configuration to determine if the container platform is configured to employ strong authenticators in the establishment of non-local maintenance and diagnostic sessions. 

If the container platform is not configured to employ strong authenticators in the establishment of non-local maintenance and diagnostic sessions, this is a finding.'
  desc 'fix', 'Configure the container platform to employ strong authenticators in the establishment of non-local maintenance and diagnostic sessions.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36042r599596_chk'
  tag severity: 'medium'
  tag gid: 'V-233106'
  tag rid: 'SV-233106r599597_rule'
  tag stig_id: 'SRG-APP-000185-CTR-000490'
  tag gtitle: 'SRG-APP-000185'
  tag fix_id: 'F-36010r598955_fix'
  tag 'documentable'
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
end
