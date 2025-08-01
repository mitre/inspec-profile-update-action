control 'SV-256979' do
  title 'OL 8 must be configured to allow sending email notifications of unauthorized configuration changes to designated personnel.'
  desc "Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the operating system. Changes to operating system configurations can have unintended side effects, some of which may be relevant to security.

Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the operating system. The operating system's IMO/ISSO and SAs must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item."
  desc 'check', 'Verify that the operating system is configured to allow sending email notifications.

Note: The "mailx" package provides the "mail" command that is used to send email messages.

Verify that the "mailx" package is installed on the system:

     $ sudo yum list installed mailx

     mailx.x86_64     12.5-29.el8     @ol8_baseos_latest
	 
If "mailx" package is not installed, this is a finding.'
  desc 'fix', 'Install the "mailx" package on the system:

     $ sudo yum install mailx'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-60657r902801_chk'
  tag severity: 'medium'
  tag gid: 'V-256979'
  tag rid: 'SV-256979r902803_rule'
  tag stig_id: 'OL08-00-010358'
  tag gtitle: 'SRG-OS-000363-GPOS-00150'
  tag fix_id: 'F-60599r902802_fix'
  tag 'documentable'
  tag cci: ['CCI-001744']
  tag nist: ['CM-3 (5)']
end
