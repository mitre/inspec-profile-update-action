control 'SV-254188' do
  title 'Nutanix AOS must notify designated personnel if baseline configurations are changed in an unauthorized manner.'
  desc "Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the operating system. Changes to operating system configurations can have unintended side effects, some of which may be relevant to security.

Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the operating system. The operating system's ISSO and SAs must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item."
  desc 'check', 'Confirm that Nutanix AOS has been set to have the Advanced Intrusion Detection Environment (AIDE) installed and enabled.

$ sudo yum list installed aide
Installed Packages
aide.x86_64 

If the aide_x86_64 package is not installed, this is a finding.

Check for the presence of a cron job running daily or weekly on the system that executes AIDE daily to scan for changes to the system baseline. 

Check the cron directories for a script file controlling the execution of the file integrity application. For example, if AIDE is installed on the system, use the following command:

$ sudo  ls -al /etc/cron.* | grep aide

If the file integrity application does not exist, or a script file controlling the execution of the file integrity application does not exist, this is a finding.'
  desc 'fix', 'Configure AIDE on Nutanix AOS by running the following command:

$ ncli cluster edit-cvm-security-params enable-aide=true'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57673r846650_chk'
  tag severity: 'medium'
  tag gid: 'V-254188'
  tag rid: 'SV-254188r846652_rule'
  tag stig_id: 'NUTX-OS-001000'
  tag gtitle: 'SRG-OS-000363-GPOS-00150'
  tag fix_id: 'F-57624r846651_fix'
  tag 'documentable'
  tag cci: ['CCI-001744']
  tag nist: ['CM-3 (5)']
end
