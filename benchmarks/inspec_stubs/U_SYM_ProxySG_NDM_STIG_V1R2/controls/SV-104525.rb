control 'SV-104525' do
  title 'Symantec ProxySG must use only approved management services protocols.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable unused or unnecessary physical and logical ports/protocols on information systems.

Network devices are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the network device must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved. Some network devices have capabilities enabled by default; if these capabilities are not necessary, they must be disabled. If a particular capability is used, then it must be documented and approved.'
  desc 'check', 'Verify unauthorized management protocols are not used on the Symantec ProxySG.

1. Log on to Web Management Console.
2. Click Configuration >> Services >> Management Services.
3. Ensure that only approved management services are enabled. "HTTP-Console", in general, should be disabled.

If Symantec ProxySG does not use only approved management services protocols, this is a finding.'
  desc 'fix', 'By default, Symantec ProxySG has only HTTPS and SSH enabled for management services. SNMP may also be enabled if needed to support the architecture. "HTTP-Console" is not approved for use in DoD.

1. Log on to Web Management Console.
2. Click Configuration >> Services >> Management Services.
3. Uncheck "enabled" next to unapproved management services such as "HTTP-Console".
4. Click "Apply".'
  impact 0.7
  ref 'DPMS Target Symantec ProxySG NDM'
  tag check_id: 'C-93885r1_chk'
  tag severity: 'high'
  tag gid: 'V-94695'
  tag rid: 'SV-104525r1_rule'
  tag stig_id: 'SYMP-NM-000220'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-100813r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
