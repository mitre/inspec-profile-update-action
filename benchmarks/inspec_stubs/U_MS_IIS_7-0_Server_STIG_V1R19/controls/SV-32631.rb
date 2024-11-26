control 'SV-32631' do
  title 'Public web server resources must not be shared with private assets.'
  desc 'It is important to segregate public web server resources from private resources located behind the DoD DMZ in order to protect private assets. When folders, drives or other resources are directly shared between the public web server and private servers the intent of data and resource segregation can be compromised. 

Resources, such as, printers, files, and folders/directories must not be shared between public web servers and assets located within the internal network.'
  desc 'check', '1. From a command prompt, type "net share" and press Enter to provide a list of available shares (including printers).  
2. To display the permissions assigned to the shares type "net share" followed by the share name found in the previous step.  

If any private assets are assigned permissions to the share, this is a finding.  If any printers are shared, this is a finding.'
  desc 'fix', 'Configure the public web server to not have a trusted relationship with any system resource that is also not accessible to the public. Web content is not to be shared via Microsoft shares or NFS mounts.'
  impact 0.5
  ref 'DPMS Target IIS Installation 7'
  tag check_id: 'C-29894r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2234'
  tag rid: 'SV-32631r2_rule'
  tag stig_id: 'WG040 IIS7'
  tag gtitle: 'WG040'
  tag fix_id: 'F-26795r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Web Administrator']
end
