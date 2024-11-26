control 'SV-207535' do
  title 'The BIND 9.x server software must run with restricted privileges.'
  desc 'Failure to provide logical access restrictions associated with changes to application configuration may have significant effects on the overall security of the system. When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system and/or application can have significant effects on the overall security of the system. Accordingly, only qualified and authorized individuals should be allowed to obtain access to application components for the purposes of initiating changes, including upgrades and modifications.'
  desc 'check', 'Verify the BIND 9.x process is not running as root:

# ps -ef | grep named

named 3015 1 0 12:59 ? 00:00:00 /usr/sbin/named -u named -t /var/named/chroot

If the output shows "/usr/sbin/named -u root", this is a finding.'
  desc 'fix', 'Configure the BIND 9.x process to run as a non-privileged user.

Restart the BIND 9.x process.'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7790r283659_chk'
  tag severity: 'medium'
  tag gid: 'V-207535'
  tag rid: 'SV-207535r612253_rule'
  tag stig_id: 'BIND-9X-001003'
  tag gtitle: 'SRG-APP-000516-DNS-000105'
  tag fix_id: 'F-7790r283660_fix'
  tag 'documentable'
  tag legacy: ['SV-86993', 'V-72369']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
