control 'SV-238471' do
  title 'The DBMS must employ cryptographic mechanisms to protect the integrity and confidentiality of non-local maintenance and diagnostic communications.'
  desc 'Non-local maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. 

The act of managing systems and applications includes the ability to access sensitive application information, such as system configuration details, diagnostic information, user information, and potentially sensitive application data. 

When applications provide a remote management capability inherent to the application, the application needs to ensure the communication channels used to remotely access the system are adequately protected.  If the communication channel is not adequately protected authentication information, application data, and configuration information could be compromised.'
  desc 'check', 'Review DBMS configuration to determine if cryptographic mechanisms are being utilized to protect the integrity and confidentiality of non-local maintenance and diagnostic communications. If not, this is a finding.'
  desc 'fix', 'Configure DBMS to utilize cryptographic mechanisms to protect the integrity and confidentiality of non-local maintenance and diagnostic communications.'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-41682r667585_chk'
  tag severity: 'medium'
  tag gid: 'V-238471'
  tag rid: 'SV-238471r667587_rule'
  tag stig_id: 'O112-C2-016000'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-41641r667586_fix'
  tag 'documentable'
  tag legacy: ['V-52299', 'SV-66515']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
