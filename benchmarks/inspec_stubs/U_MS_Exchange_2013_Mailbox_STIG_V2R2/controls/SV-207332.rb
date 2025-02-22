control 'SV-207332' do
  title 'Exchange must provide Mailbox databases in a highly available and redundant configuration.'
  desc 'To protect Exchange Server mailbox databases and the data they contain by configuring Mailbox servers and databases for high availability and site resilience.

A database availability group (DAG) is a component of the Mailbox server high availability and site resilience framework built into Microsoft Exchange Server 2013. A DAG is a group of Mailbox servers that hosts a set of databases and provides automatic database-level recovery from failures that affect individual servers or databases.
A DAG is a boundary for mailbox database replication and database and server switchovers and failovers. 

Any server in a DAG can host a copy of a mailbox database from any other server in the DAG. When a server is added to a DAG, it works with the other servers in the DAG to provide automatic recovery from failures that affect mailbox databases, such as a disk, server, or network failure.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Determine if the Exchange Mailbox databases are using redundancy.

Open an Exchange Admin Center.

Navigate to and select Microsoft Exchange >> Microsoft Exchange On - Premises <server.domain> >> Organization Configuration >> Mailbox.

In the right pane, if two or more Mailbox servers are not listed, this is a finding.

Note: The EDSP must indicate what availability the system must have, as approved by the ISSO. This can be used for justification when determining finding and possibly a severity downgrade.'
  desc 'fix', 'Update the EDSP.

Add two or more Mailbox servers to the database availability group.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7590r393509_chk'
  tag severity: 'medium'
  tag gid: 'V-207332'
  tag rid: 'SV-207332r615936_rule'
  tag stig_id: 'EX13-MB-000335'
  tag gtitle: 'SRG-APP-000435'
  tag fix_id: 'F-7590r393510_fix'
  tag 'documentable'
  tag legacy: ['SV-84683', 'V-70061']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
