control 'SV-237166' do
  title 'ColdFusion must only allow approved file extensions.'
  desc 'Application servers provide a myriad of differing processes, features, and functionalities. Some of these processes may be deemed to be unnecessary or too unsecure to run on a production DoD system. One area of concern is the file types that can be included in cfm and cfml files by programmers.  To control what types of technologies are used in the development of hosted applications, a default whitelist can be created and approved by the ISSO.  This list includes only those file extensions that are used by the hosted applications.  By default, cfm and cfml are included and do not have to be specified.  The list must not contain the wildcard string "*.*".'
  desc 'check', 'Within the Administrator Console, navigate to the "Settings" page under the "Server Settings" menu.  If "Allowed file extensions for CFInclude tag" is empty, this is not a finding.

If the "Allowed file extensions for CFInclude tag" contains the wildcard string "*.*" or if the list of file extensions is not the list approved by the ISSO, this is a finding.'
  desc 'fix', 'Navigate to the "Settings" page under the "Server Settings" menu.  Enter the list of approved file extensions in the "Allowed file extensions for CFInclude tag" field and select the "Submit Changes" button.  A blank list will only allow cfm and cfml files to be included and fulfills this requirement.'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40385r641591_chk'
  tag severity: 'medium'
  tag gid: 'V-237166'
  tag rid: 'SV-237166r641593_rule'
  tag stig_id: 'CF11-03-000096'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-40348r641592_fix'
  tag 'documentable'
  tag legacy: ['SV-76895', 'V-62405']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
