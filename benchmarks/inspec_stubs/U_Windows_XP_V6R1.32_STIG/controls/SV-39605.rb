control 'SV-39605' do
  title 'The Task Scheduler service must be disabled.'
  desc 'Unnecessary services increase the attack surface of a system. Some services may be run under the local System account.  Compromising a service could allow an intruder to obtain system permissions and open the system to a variety of attacks.'
  desc 'check', 'Select “Start”.
Right-click the “My Computer” icon on the Start menu or the desktop.
Select “Manage” from the drop-down menu.
Expand the “Services and Applications” object in the Tree window.
Select the “Services” object.

If the Task Scheduler service is not disabled, and the site has not documented required tasks, this is a finding. 

Documentable Explanation:  If the Task Scheduler service is required it will be documented with the IAO to include the required tasks.  Scheduled tasks will be regularly reviewed for unapproved tasks.'
  desc 'fix', 'Configure the system to disable Task Scheduler.'
  impact 0.7
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-38508r1_chk'
  tag severity: 'high'
  tag gid: 'V-30037'
  tag rid: 'SV-39605r1_rule'
  tag stig_id: 'WINSV-000106'
  tag gtitle: 'Task Scheduler Service'
  tag fix_id: 'F-33770r1_fix'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECSC-1'
end
