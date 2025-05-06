control 'SV-213524' do
  title 'Any unapproved applications must be removed.'
  desc 'Extraneous services and applications running on an application server expands the attack surface and increases risk to the application server. Securing any server involves identifying and removing any unnecessary services and, in the case of an application server, unnecessary and/or unapproved applications.'
  desc 'check', 'Log on to the OS of the JBoss server with OS permissions that allow access to JBoss. 
Using the relevant OS commands and syntax, cd to the <JBOSS_HOME>/bin/ folder. 
Run the jboss-cli script. 
Connect to the server and authenticate. 
Run the command:

ls /deployment

The list of deployed applications is displayed.  Have the system admin identify the applications listed and confirm they are approved applications.

If the system admin cannot provide documentation proving their authorization for deployed applications, this is a finding.'
  desc 'fix', 'Identify, authorize, and document all applications that are deployed to the application server.  Remove unauthorized applications.'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14747r296238_chk'
  tag severity: 'medium'
  tag gid: 'V-213524'
  tag rid: 'SV-213524r615939_rule'
  tag stig_id: 'JBOS-AS-000250'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-14745r296239_fix'
  tag 'documentable'
  tag legacy: ['SV-76763', 'V-62273']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
