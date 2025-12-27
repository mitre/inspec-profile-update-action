control 'SV-33134' do
  title 'Only web sites that have been fully reviewed and tested must exist on a production web server.'
  desc 'In the case of a production web server, areas for content development and testing will not exist, as this type of content is only permissible on a development web site. The process of developing on a functional production web site entails a degree of trial and error and repeated testing. This process is often accomplished in an environment where debugging, sequencing, and formatting of content are the main goals. The opportunity for a malicious user to obtain files that reveal business logic and login schemes is high in this situation. The existence of such immature content on a web server represents a significant security risk that is totally avoidable.'
  desc 'check', 'Query the ISSO, the SA, and the web administrator to find out if development web sites are being housed on production web servers. 

Definition: A production web server is any web server connected to a production network, regardless of its role.

Proposed Questions:
Do you have development sites on your production web server?
What is your process to get development web sites / content posted to the production server?
Do you use under construction notices on production web pages?

The reviewer can also do a manual check or perform a navigation of the web site via a browser to confirm the information provided from interviewing the web staff. Graphics or texts which proclaim Under Construction or Under Development are frequently used to mark folders or directories in that status.

If Under Construction or Under Development web content is discovered on the production web server, this is a finding.'
  desc 'fix', 'The presences of portions of the web site that proclaim Under Construction or Under Development are clear indications that a production web server is being used for development. The web administrator will ensure that all pages that are in development are not installed on a production web server.'
  impact 0.5
  ref 'DPMS Target Apache Site 2.0'
  tag check_id: 'C-33786r2_chk'
  tag severity: 'medium'
  tag gid: 'V-2254'
  tag rid: 'SV-33134r2_rule'
  tag stig_id: 'WG260 W22'
  tag gtitle: 'WG260'
  tag fix_id: 'F-29430r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'ECSC-1'
end
