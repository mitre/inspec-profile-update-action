control 'SV-205245' do
  title 'The DNS Name Server software must run with restricted privileges.'
  desc 'Failure to provide logical access restrictions associated with changes to application configuration may have significant effects on the overall security of the system. When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system and/or application can have significant effects on the overall security of the system. Accordingly, only qualified and authorized individuals should be allowed to obtain access to application components for the purposes of initiating changes, including upgrades and modifications. 

Logical access restrictions include, for example, controls that restrict access to workflow automation, media libraries, abstract layers (e.g., changes implemented into third-party interfaces rather than directly into information systems), and change windows (e.g., changes occur only during specified times, making unauthorized changes easy to discover).

If the name server software is run as a privileged user (e.g., root in Unix systems), any break-in into the software can have disastrous consequences in terms of resources resident in the name server platform. Specifically, a hacker who breaks into the software acquires unrestricted access and therefore can execute any commands or modify or delete any files. It is necessary to run the name server software as a non-privileged user with access restricted to specified directories to contain damages resulting from break-in.'
  desc 'check', 'Review the account under which the DNS software is running and determine the permissions that account has been assigned.

If the account under which the DNS software is running has not been restricted to the least privileged permissions required for the purpose of running the software, this is a finding.'
  desc 'fix', 'Configured the permissions of the account being used to run the DNS software so that it has the least privileges required under which to run the DNS software.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5512r392648_chk'
  tag severity: 'medium'
  tag gid: 'V-205245'
  tag rid: 'SV-205245r879887_rule'
  tag stig_id: 'SRG-APP-000516-DNS-000105'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-5512r392649_fix'
  tag 'documentable'
  tag legacy: ['SV-69197', 'V-54951']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
