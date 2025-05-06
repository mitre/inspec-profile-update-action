control 'SV-253744' do
  title 'When updates are applied to the MariaDB software, any software components that have been replaced or made unnecessary must be removed.'
  desc 'Previous versions of MariaDB components that are not removed from the information system after updates have been installed may be exploited by adversaries. 

MariaDB may remove older versions of software automatically from the information system. In other cases, manual review and removal will be required. In planning installations and upgrades, organizations must include steps (automated, manual, or both) to identify and remove the outdated modules.

A transition period may be necessary when both the old and the new software are required. This should be taken into account in the planning.'
  desc 'check', 'If updating through a repository using yum, apt, etc., all MariaDB packages should be updated/upgraded at the same time. 

Use the package manager to verify no outdated packages remain. Example: 

$ sudo yum list installed | grep -i mariadb

If older packages remain, this is a finding.'
  desc 'fix', 'If after the upgrade outdated packages remain, update them if needed or remove. Example: 

$ sudo yum remove package_name'
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57196r841755_chk'
  tag severity: 'medium'
  tag gid: 'V-253744'
  tag rid: 'SV-253744r841757_rule'
  tag stig_id: 'MADB-10-009200'
  tag gtitle: 'SRG-APP-000454-DB-000389'
  tag fix_id: 'F-57147r841756_fix'
  tag 'documentable'
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
end
