control 'SV-207286' do
  title 'Exchange Mailbox databases must reside on a dedicated partition.'
  desc 'In the same way that added security layers can provide a cumulative positive effect on security posture, multiple applications can provide a cumulative negative effect. A vulnerability and subsequent exploit to one application can lead to an exploit of other applications sharing the same security context. For example, an exploit to a web server process that leads to unauthorized administrative access to the host system can most likely lead to a compromise of all applications hosted by the same system.

Email services should be installed to a discrete set of directories, on a partition that does not host other applications. Email services should never be installed on a Domain Controller/Directory Services server.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP). 

Determine the location where the Exchange Mailbox databases reside.

Open the Exchange Management Shell and enter the following command:

Get-MailboxDatabase | Select Name, Identity, EdbFilePath

Open Windows Explorer and navigate to and verify the mailbox databases are on a dedicated partition.

If the mailbox databases are not on a dedicated partition, this is a finding.'
  desc 'fix', 'Update the EDSP.

Configure the mailbox databases on a dedicated partition.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7544r393371_chk'
  tag severity: 'medium'
  tag gid: 'V-207286'
  tag rid: 'SV-207286r615936_rule'
  tag stig_id: 'EX13-MB-000100'
  tag gtitle: 'SRG-APP-000211'
  tag fix_id: 'F-7544r393372_fix'
  tag 'documentable'
  tag legacy: ['SV-84601', 'V-69979']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
