control 'SV-32478' do
  title 'All web server documentation, sample code, example applications, and tutorials must be removed from a production web server.'
  desc 'Web server documentation, sample code, example applications, and tutorials may be an exploitable threat to a web server. A production web server may only contain components that are operationally necessary (i.e., compiled code, scripts, web content, etc.). Delete all directories containing samples and any scripts used to execute the samples.'
  desc 'check', '1. Navigate to the following folders:
  inetpub\\AdminScripts
  inetpub\\scripts\\IISSamples
  Program Files\\Common Files\\System\\msadc
  Program Files (x86)\\Common Files\\System\\msadc
2. If the folders contain sample code and documentation, this is a finding.

Note: Any non-executable web server documentation or sample file found on the production web server and accessible to web users or non-administrators will be a CAT III finding.
Any non-executable web server documentation or sample file found on the production web server and accessible only to SAs or to web administrators is permissible and is not a finding.'
  desc 'fix', 'Remove sample code and documentation from the web server.'
  impact 0.7
  ref 'DPMS Target IIS Installation 7'
  tag check_id: 'C-32792r3_chk'
  tag severity: 'high'
  tag gid: 'V-13621'
  tag rid: 'SV-32478r3_rule'
  tag stig_id: 'WG385 IIS7'
  tag gtitle: 'WG385'
  tag fix_id: 'F-29072r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', 'Web Administrator']
end
