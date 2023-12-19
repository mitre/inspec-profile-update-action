control 'SV-228373' do
  title 'Exchange Mailbox databases must reside on a dedicated partition.'
  desc 'In the same way that added security layers can provide a cumulative positive effect on security posture, multiple applications can provide a cumulative negative effect. A vulnerability and subsequent exploit to one application can lead to an exploit of other applications sharing the same security context. For example, an exploit to a web server process that leads to unauthorized administrative access to the host system can most likely lead to a compromise of all applications hosted by the same system.

Email services should be installed to a discrete set of directories on a partition that does not host other applications. Email services should never be installed on a Domain Controller/Directory Services server.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP) or document that contains this information.

Determine the location where the Exchange Mailbox databases reside.

Open the Exchange Management Shell and enter the following command:

Get-MailboxDatabase | Select Name, Identity, EdbFilePath

Open Windows Explorer, navigate to the mailbox databases, and verify they are on a dedicated partition.

If the mailbox databases are not on a dedicated partition, this is a finding.'
  desc 'fix', 'Update the EDSP to specify the location where the Exchange Mailbox databases reside or verify that this information is documented by the organization.

Configure the mailbox databases on a dedicated partition.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30606r496915_chk'
  tag severity: 'medium'
  tag gid: 'V-228373'
  tag rid: 'SV-228373r612748_rule'
  tag stig_id: 'EX16-MB-000200'
  tag gtitle: 'SRG-APP-000211'
  tag fix_id: 'F-30591r496916_fix'
  tag 'documentable'
  tag legacy: ['SV-95371', 'V-80661']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
