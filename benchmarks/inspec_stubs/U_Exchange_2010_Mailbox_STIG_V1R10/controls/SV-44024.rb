control 'SV-44024' do
  title 'Mailbox databases must reside on a dedicated partition.'
  desc 'In the same way that added security layers can provide a cumulative positive effect on security posture, multiple applications can provide a cumulative negative effect. A vulnerability and subsequent exploit to one application can lead to an exploit of other applications sharing the same security context. For example, an exploit to a web server process that leads to unauthorized administrative access to the host system can most likely lead to a compromise of all applications hosted by the same system.

Email services should be installed to a discrete set of directories, on a partition that does not host other applications.   Email services should never be installed on a Domain Controller / Directory Services server.'
  desc 'check', 'Obtain the Email Domain Security Plan (EDSP) and locate the assigned directory for the mailbox server under review.

Open the Exchange Management Shell and enter the following command to determine the drives the mailbox databases are located.

Get-MailboxDatabase | Select Name, Identity, EdbFilePath

Open Windows Explorer and use the file and folder properties function to verify the mailbox databases are on a dedicated partition. If not, this is a finding.'
  desc 'fix', 'Configure the system to meet the separate partition requirement.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41710r1_chk'
  tag severity: 'medium'
  tag gid: 'V-33604'
  tag rid: 'SV-44024r1_rule'
  tag stig_id: 'Exch-1-318'
  tag gtitle: 'Exch-1-318'
  tag fix_id: 'F-37495r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
