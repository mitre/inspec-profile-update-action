control 'SV-256983' do
  title 'The SUSE operating system must be configured to allow sending email notifications of unauthorized configuration changes to designated personnel.'
  desc "Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the operating system. Changes to operating system configurations can have unintended side effects, some of which may be relevant to security.

Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the operating system. The operating system's IMO/ISSO and SAs must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item."
  desc 'check', 'Verify that the operating system is configured to allow sending email notifications.

Note: The "mailx" package provides the "mail" command that is used to send email messages.

Verify that the "mailx" package is installed on the system:

     > sudo zypper se mailx

     i | mailx | A MIME-Capable Implementation of the mailx Command | package
	 
If "mailx" package is not installed, this is a finding.'
  desc 'fix', 'Install the "mailx" package on the system:

     > sudo zypper install mailx'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-60661r902847_chk'
  tag severity: 'medium'
  tag gid: 'V-256983'
  tag rid: 'SV-256983r902849_rule'
  tag stig_id: 'SLES-15-010418'
  tag gtitle: 'SRG-OS-000363-GPOS-00150'
  tag fix_id: 'F-60603r902848_fix'
  tag 'documentable'
  tag cci: ['CCI-001744']
  tag nist: ['CM-3 (5)']
end
