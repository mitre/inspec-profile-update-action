control 'SV-237170' do
  title 'ColdFusion must have Remote Development Services (RDS) disabled.'
  desc 'Application servers provide a myriad of differing processes, features, and functionalities. Some of these processes may be deemed to be unnecessary or too unsecure to run on a production DoD system.  Remote Development Services (RDS) is used in a development environment to  allow authenticated users access to the server using special features within code editors like Dreamweaver, HomeSite+, ColdFusion Studio, and Eclipse to obtain information from the server.   For example, developers can determine what data sources exist, query them, build code based on them, and more.  RDS also enables access from within the editors to files on the server (even remotely) over HTTP, as an alternative to FTP.  This feature is not meant for production environments.'
  desc 'check', 'Within the Administrator Console, navigate to the "RDS" page under the "Security" menu.

If "Enable RDS Service" is checked, this is a finding.'
  desc 'fix', 'Navigate to the "RDS" page under the "Security" menu.  Uncheck "Enable RDS Service" and select the "Submit Changes" button.'
  impact 0.7
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40389r641603_chk'
  tag severity: 'high'
  tag gid: 'V-237170'
  tag rid: 'SV-237170r641605_rule'
  tag stig_id: 'CF11-03-000100'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-40352r641604_fix'
  tag 'documentable'
  tag legacy: ['SV-76903', 'V-62413']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
