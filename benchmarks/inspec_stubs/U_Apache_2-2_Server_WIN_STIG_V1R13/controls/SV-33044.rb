control 'SV-33044' do
  title 'Public web server resources must not be shared with private assets.'
  desc 'It is important to segregate public web server resources from private resources located behind the DoD DMZ in order to protect private assets. When folders, drives or other resources are directly shared between the public web server and private servers the intent of data and resource segregation can be compromised.'
  desc 'check', 'The reviewer should query the ISSO, the SA, or the web administrator as necessary to determine if the public web server has a two-way trusted relationship with any private asset. Private web server resources (e.g., drives, folders, printers, etc.) will not be directly mapped to or shared with public web servers.

The following check indicates an inappropriate sharing of public web server resources:

Navigate to the web server content folders/directories. These directories must not be shared. On the web server content folder, right-click on Properties, then select sharing. All entries must be disabled. 

If sharing is selected for any web folder, this is a finding.

The following checks indicate inappropriate sharing of private resources with the public web server:

1. From a command prompt, type net share and Enter. This will provide a list of available shares. 
2. Check to see if file and printer or file-sharing is enabled under the Network icon in the Control Panel. 

If private resources (e.g., drives, partitions, folders/directories, printers, etc.) are shared with the public web server, this is a finding.'
  desc 'fix', 'Configure the public web server to not have a trusted relationship with any system resource that is not accessible to the public. Web content is not to be shared via Microsoft shares or NFS mounts.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33720r2_chk'
  tag severity: 'medium'
  tag gid: 'V-2234'
  tag rid: 'SV-33044r2_rule'
  tag stig_id: 'WG040 W22'
  tag gtitle: 'WG040'
  tag fix_id: 'F-29355r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
