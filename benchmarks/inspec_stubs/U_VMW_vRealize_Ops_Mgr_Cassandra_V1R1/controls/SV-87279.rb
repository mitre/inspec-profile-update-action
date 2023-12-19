control 'SV-87279' do
  title 'The Cassandra software, including configuration files, must be stored in dedicated directories, or direct-access storage device (DASD) pools, separate from the host OS and other applications.'
  desc "When dealing with change control issues, it should be noted any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system.

Multiple applications can provide a cumulative negative effect. A vulnerability and subsequent exploit to one application can lead to an exploit of other applications sharing the same security context. For example, an exploit to a web server process that leads to unauthorized administrative access to host system directories can most likely lead to a compromise of all applications hosted by the same system. Database software not installed using dedicated directories both threatens and is threatened by other hosted applications. Access controls defined for one application may by default provide access to the other application's database objects or directories. Any method that provides any level of separation of security context assists in the protection between applications."
  desc 'check', 'Review the Cassandra Server Configuration to ensure its software, including configuration files, is stored in dedicated directories, or direct-access storage device (DASD) pools, separate from the host OS and other applications.

Run following commands from Cassandra host server console: "cd $VCOPS_BASE/Cassandra/<installed Cassandra release name (current example - apache-cassandra-2.1.8)> ls -l"

If the Cassandra software, including configuration files, is not stored separate from the host OS and other applications, this is a finding.'
  desc 'fix', 'Configure the Cassandra Server software, including configuration files, to be stored in dedicated directories, or direct-access storage device (DASD) pools, separate from the host OS and other applications.

Install all applications on directories separate from the DBMS software library directory. Relocate any directories or reinstall other application software that currently shares the DBMS software library directory.'
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72803r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72647'
  tag rid: 'SV-87279r1_rule'
  tag stig_id: 'VROM-CS-000100'
  tag gtitle: 'SRG-APP-000133-DB-000199'
  tag fix_id: 'F-79051r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
