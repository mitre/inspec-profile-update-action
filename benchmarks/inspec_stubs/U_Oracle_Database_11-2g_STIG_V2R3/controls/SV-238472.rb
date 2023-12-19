control 'SV-238472' do
  title 'The DBMS must employ strong identification and authentication techniques when establishing non-local maintenance and diagnostic sessions.'
  desc 'Non-local maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. 

The act of managing systems and applications includes the ability to access sensitive application information, such as system configuration details, diagnostic information, user information, and potentially sensitive application data. 

When applications provide a remote management capability inherent to the application, the application needs to ensure the identification and authentication techniques used to remotely access the system are strong enough to protect the system. If the communication channel is not adequately protected, authentication information, application data, and configuration information could be compromised.'
  desc 'check', 'Review DBMS settings to determine whether strong identification and authentication techniques are required for non-local maintenance and diagnostic sessions. If strong identification and authentication techniques are not required, this is a finding.'
  desc 'fix', 'Configure DBMS settings to use strong identification and authentication techniques for non-local maintenance and diagnostic sessions.'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-41683r667588_chk'
  tag severity: 'medium'
  tag gid: 'V-238472'
  tag rid: 'SV-238472r667590_rule'
  tag stig_id: 'O112-C2-016100'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-41642r667589_fix'
  tag 'documentable'
  tag legacy: ['V-52301', 'SV-66517']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
